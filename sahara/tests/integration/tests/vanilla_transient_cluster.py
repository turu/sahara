# Copyright (c) 2014 Mirantis Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time

import saharaclient.api.base as sab

from sahara.openstack.common import timeutils
from sahara.tests.integration.tests import base
from sahara.tests.integration.tests import edp
from sahara.utils import edp as utils_edp


class TransientClusterTest(edp.EDPTest):
    @base.skip_test(
        'SKIP_TRANSIENT_CLUSTER_TEST',
        message='Test for transient cluster was skipped.')
    def transient_cluster_testing(self, plugin_config, floating_ip_pool,
                                  internal_neutron_net):
        cluster_template_id = self.create_cluster_template(
            name='test-transient-cluster-template-vanilla',
            plugin_config=self.vanilla_config,
            description=('test cluster template for transient cluster '
                         'of Vanilla plugin'),
            cluster_configs={},
            node_groups=[
                dict(
                    name='master-node',
                    flavor_id=self.flavor_id,
                    node_processes=['namenode', 'oozie', 'jobtracker'],
                    floating_ip_pool=floating_ip_pool,
                    count=1),
                dict(
                    name='worker-node',
                    flavor_id=self.flavor_id,
                    node_processes=['datanode', 'tasktracker'],
                    floating_ip_pool=floating_ip_pool,
                    count=1)
            ],
            net_id=internal_neutron_net
        )

        try:
            # create a transient cluster
            try:
                cluster_name = (self.common_config.CLUSTER_NAME + '-transient-'
                                + plugin_config.PLUGIN_NAME)
                self.create_cluster(
                    name=cluster_name,
                    plugin_config=plugin_config,
                    cluster_template_id=cluster_template_id,
                    description='test transient cluster',
                    cluster_configs={},
                    is_transient=True
                )
            except Exception:
                self.delete_objects(cluster_id=self.cluster_id)
                raise

            # check EDP
            path = 'sahara/tests/integration/tests/resources/'
            pig_job_data = open(path + 'edp-job.pig').read()
            pig_lib_data = open(path + 'edp-lib.jar').read()
            self.edp_testing(job_type=utils_edp.JOB_TYPE_PIG,
                             job_data_list=[{'pig': pig_job_data}],
                             lib_data_list=[{'jar': pig_lib_data}])

            # set timeout in seconds
            timeout = self.common_config.TRANSIENT_CLUSTER_TIMEOUT * 60
            s_time = timeutils.utcnow()
            raise_failure = True
            # wait for cluster deleting
            while timeutils.delta_seconds(
                    s_time, timeutils.utcnow()) < timeout:
                try:
                    self.sahara.clusters.get(self.cluster_id)
                except sab.APIException as api_ex:
                    if 'not found' in api_ex.message:
                        raise_failure = False
                        break
                time.sleep(2)

            if raise_failure:
                self.delete_objects(cluster_id=self.cluster_id)
                self.fail('Transient cluster has not been deleted within %s '
                          'minutes.'
                          % self.common_config.TRANSIENT_CLUSTER_TIMEOUT)
        finally:
            self.delete_objects(cluster_template_id=cluster_template_id)
