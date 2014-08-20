# Copyright (c) 2013 Mirantis Inc.
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

from novaclient import exceptions as nova_exceptions
from oslo.config import cfg
import six

from sahara import conductor as c
from sahara import context
from sahara.openstack.common import excutils
from sahara.openstack.common import log as logging
from sahara.plugins import base as plugin_base
from sahara.service import engine as e
from sahara.service import networks
from sahara.service import volumes
from sahara.service import retryable_operation as r
from sahara.service import api
from sahara.utils import general as g
from sahara.utils.openstack import nova


conductor = c.API

opts = [
    cfg.IntOpt("direct_node_spawn_slot_time_ms",
               default=200,
               help="Amount of milliseconds used as the time unit for Binary Exponential Backoff algorithm, "
                    "used by the Direct Engine, when node spawning fails and has to be retried."),
    cfg.IntOpt("direct_node_spawn_retries_limit",
               default=10,
               help="Max number of retries before the Direct Engine declares node spawning as failed."),
    cfg.BoolOpt("direct_suppress_node_spawn_failure",
                default=False,
                help="If set to true, when node spawning fails, the Direct Engine will check if a cluster "
                     "created without the offending node can pass plugin specific validation and if so, "
                     "will continue the cluster creation process without that node."),
    cfg.IntOpt("direct_node_scheduling_timeout_s",
               default=10,
               help="Sets timeout after which node spawning is declared as failed. It's used to prevent VMs from"
                    "being forever stuck at scheduling phase of build"),
    cfg.IntOpt("direct_node_scheduling_check_interval_s",
               default=1,
               help="Direct engine will check if a node has already been scheduled, "
                    "every direct_node_scheduling_check_interval_s seconds")
]

CONF = cfg.CONF
CONF.register_opts(opts)
LOG = logging.getLogger(__name__)


def try_force_delete(name):
    server_list = nova.client().servers.list(True, {"name": name})
    if len(server_list) > 0:
        server = server_list[0]
        LOG.debug("Force deleting instance name %s" % server.name)
        try:
            server.reset_state()
        except Exception as e:
            LOG.debug("Exception occurred during resetting state of an instance name %s. Message: %s" %
                      (name, e.message))
        try:
            server.force_delete()
        except Exception as e:
            LOG.debug("Exception occurred during force deleting of an instance name %s. Message: %s" %
                      (name, e.message))
            server.delete()
    else:
        LOG.debug("Instance name %s not present in nova. Could not force delete")


def try_shutdown(cluster, engine, idx, instance, node_group):
    LOG.warning("Spawning of node id %s from node_group %s for cluster %s, failed. "
                "Removing the instance %s from cluster..." %
                (str(idx), str(node_group.id), str(cluster.id), str(instance.id)))
    try:
        engine._shutdown_instance(instance)
    except Exception as e:
        LOG.info("Removed instance was not present in the database. Exception caught: %s" % e.message)


def await_deleted(name):
    LOG.debug("Waiting for instance name %s to be deleted from nova" % name)
    while len(nova.client().servers.list(True, {"name": name})) > 0:
        try_force_delete(name)
        context.sleep(1)
    LOG.debug("Instance name %s no longer present in nova. Removed." % name)


def remove_failed_instance(self, cluster, node_group, idx, aa_groups):
    ctx = context.ctx()
    name = '%s-%s-%03d' % (cluster.name, node_group.name, idx)
    cluster = conductor.cluster_get(ctx, cluster)
    instance = g.get_instance_by_name(cluster, name)
    engine = api.INFRA
    if instance is None:
        LOG.warning("Failed instance id %s from node_group %s for cluster %s was not present in the cluster. "
                    "Removing anyway..." % ((str(idx), str(node_group.id), str(cluster.id))))
        try_force_delete(name)
    else:
        try_shutdown(cluster, engine, idx, instance, node_group)
    await_deleted(name)


def validate_cluster_after_spawn_failure(self, cluster, node_group, idx, aa_groups):
    LOG.info("Validating cluster %s after spawning of node %s from node group %s failed..."
             % (str(cluster.id), str(idx), str(node_group.id)))
    plugin = plugin_base.PLUGINS.get_plugin(cluster.plugin_name)
    ctx = context.ctx()
    cluster = conductor.cluster_get(ctx, cluster)
    plugin.validate(cluster)


class DirectEngine(e.Engine):
    def get_node_group_image_username(self, node_group):
        image_id = node_group.get_image_id()
        return nova.client().images.get(image_id).username

    def create_cluster(self, cluster):
        ctx = context.ctx()
        try:
            # create all instances
            conductor.cluster_update(ctx, cluster, {"status": "Spawning"})
            LOG.info(g.format_cluster_status(cluster))
            self._create_instances(cluster)

            # wait for all instances are up and networks ready
            cluster = conductor.cluster_update(ctx, cluster,
                                               {"status": "Waiting"})
            LOG.info(g.format_cluster_status(cluster))

            instances = g.get_instances(cluster)

            self._await_active(cluster, instances)

            self._assign_floating_ips(instances)

            self._await_networks(cluster, instances)

            cluster = conductor.cluster_get(ctx, cluster)

            # attach volumes
            volumes.attach(cluster)

            # prepare all instances
            cluster = conductor.cluster_update(ctx, cluster,
                                               {"status": "Preparing"})
            LOG.info(g.format_cluster_status(cluster))

            self._configure_instances(cluster)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self._log_operation_exception(
                    "Can't start cluster '%s' (reason: %s)", cluster, ex)

                cluster = conductor.cluster_update(
                    ctx, cluster, {"status": "Error",
                                   "status_description": str(ex)})
                LOG.info(g.format_cluster_status(cluster))
                self._rollback_cluster_creation(cluster, ex)

    def scale_cluster(self, cluster, node_group_id_map):
        ctx = context.ctx()

        instance_ids = []
        try:
            instance_ids = self._scale_cluster_instances(cluster,
                                                         node_group_id_map)

            cluster = conductor.cluster_get(ctx, cluster)
            g.clean_cluster_from_empty_ng(cluster)

            cluster = conductor.cluster_get(ctx, cluster)
            instances = g.get_instances(cluster, instance_ids)

            self._await_active(cluster, instances)

            self._assign_floating_ips(instances)

            self._await_networks(cluster, instances)

            cluster = conductor.cluster_get(ctx, cluster)

            volumes.attach_to_instances(
                g.get_instances(cluster, instance_ids))

        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self._log_operation_exception(
                    "Can't scale cluster '%s' (reason: %s)", cluster, ex)

                cluster = conductor.cluster_get(ctx, cluster)
                self._rollback_cluster_scaling(
                    cluster, g.get_instances(cluster, instance_ids), ex)
                instance_ids = []

                cluster = conductor.cluster_get(ctx, cluster)
                g.clean_cluster_from_empty_ng(cluster)
                if cluster.status == 'Decommissioning':
                    cluster = conductor.cluster_update(ctx, cluster,
                                                       {"status": "Error"})
                else:
                    cluster = conductor.cluster_update(ctx, cluster,
                                                       {"status": "Active"})

                LOG.info(g.format_cluster_status(cluster))

        # we should be here with valid cluster: if instances creation
        # was not successful all extra-instances will be removed above
        if instance_ids:
            self._configure_instances(cluster)
        return instance_ids

    def _generate_anti_affinity_groups(self, cluster):
        aa_groups = {}

        for node_group in cluster.node_groups:
            for instance in node_group.instances:
                if instance.instance_id:
                    for process in node_group.node_processes:
                        if process in cluster.anti_affinity:
                            aa_group = aa_groups.get(process, [])
                            aa_group.append(instance.instance_id)
                            aa_groups[process] = aa_group

        return aa_groups

    def _create_instances(self, cluster):
        ctx = context.ctx()

        aa_groups = {}

        with context.ThreadGroup() as tg:
            for node_group in cluster.node_groups:
                count = node_group.count
                conductor.node_group_update(ctx, node_group, {'count': 0})
                for idx in six.moves.xrange(1, count + 1):
                    tg.spawn("instance-creating-%s-%s-%s" % (cluster.id, node_group.id, idx),
                             self._run_instance, cluster, node_group, idx, aa_groups)

    def _scale_cluster_instances(self, cluster, node_group_id_map):
        ctx = context.ctx()
        aa_groups = self._generate_anti_affinity_groups(cluster)
        instances_to_delete = []
        node_groups_to_enlarge = []

        for node_group in cluster.node_groups:
            new_count = node_group_id_map[node_group.id]

            if new_count < node_group.count:
                instances_to_delete += node_group.instances[new_count:
                                                            node_group.count]
            elif new_count > node_group.count:
                node_groups_to_enlarge.append(node_group)

        if instances_to_delete:
            cluster = conductor.cluster_update(
                ctx, cluster, {"status": "Deleting Instances"})
            LOG.info(g.format_cluster_status(cluster))

            for instance in instances_to_delete:
                self._shutdown_instance(instance)

        cluster = conductor.cluster_get(ctx, cluster)

        instances_to_add = []
        if node_groups_to_enlarge:
            cluster = conductor.cluster_update(ctx, cluster,
                                               {"status": "Adding Instances"})
            LOG.info(g.format_cluster_status(cluster))
            for node_group in node_groups_to_enlarge:
                count = node_group_id_map[node_group.id]
                for idx in six.moves.xrange(node_group.count + 1, count + 1):
                    instance_id = self._run_instance(cluster, node_group, idx,
                                                     aa_groups)
                    if instance_id != r.FAILURE_SUPPRESSED:
                        instances_to_add.append(instance_id)

        return instances_to_add

    def _find_by_id(self, lst, id):
        for obj in lst:
            if obj.id == id:
                return obj

        return None

    @r.retryable(CONF.direct_node_spawn_slot_time_ms, CONF.direct_node_spawn_retries_limit, remove_failed_instance,
                 CONF.direct_suppress_node_spawn_failure, validate_cluster_after_spawn_failure)
    def _run_instance(self, cluster, node_group, idx, aa_groups):
        """Create instance using nova client and persist them into DB."""
        ctx = context.ctx()
        name = '%s-%s-%03d' % (cluster.name, node_group.name, idx)

        userdata = self._generate_user_data_script(node_group, name)

        # aa_groups: node process -> instance ids
        aa_ids = []
        for node_process in node_group.node_processes:
            aa_ids += aa_groups.get(node_process) or []

        # create instances only at hosts w/ no instances
        # w/ aa-enabled processes
        hints = {'different_host': list(set(aa_ids))} if aa_ids else None

        if CONF.use_neutron:
            net_id = cluster.neutron_management_network
            nics = [{"net-id": net_id, "v4-fixed-ip": ""}]

            nova_instance = nova.client().servers.create(
                name, node_group.get_image_id(), node_group.flavor_id,
                scheduler_hints=hints, userdata=userdata,
                key_name=cluster.user_keypair_id,
                nics=nics)
        else:
            nova_instance = nova.client().servers.create(
                name, node_group.get_image_id(), node_group.flavor_id,
                scheduler_hints=hints, userdata=userdata,
                key_name=cluster.user_keypair_id)

        instance_id = conductor.instance_add(ctx, node_group,
                                             {"instance_id": nova_instance.id,
                                              "instance_name": name})

        self._await_scheduled(nova_instance)

        # save instance id to aa_groups to support aa feature
        for node_process in node_group.node_processes:
            if node_process in cluster.anti_affinity:
                aa_group_ids = aa_groups.get(node_process, [])
                aa_group_ids.append(nova_instance.id)
                aa_groups[node_process] = aa_group_ids

        LOG.info("Successfully created and scheduled instance name: %s, id: %s" % (name, nova_instance.id))

        return instance_id

    def _await_scheduled(self, instance):
        LOG.info("Waiting for instance %s to be scheduled." % instance.name)
        slept_total = 0
        while slept_total < CONF.direct_node_scheduling_timeout_s:
            if self._check_if_scheduled(instance):
                return
            slept_total += CONF.direct_node_scheduling_check_interval_s
            context.sleep(CONF.direct_node_scheduling_check_interval_s)
        raise RuntimeError("node %s was not scheduled within given time" % instance.name)

    def _check_if_scheduled(self, instance):
        server = nova.client().servers.get(instance.id)
        if server.status == 'ERROR':
            raise RuntimeError("node %s has error status with fault: %s" % (server.name, server.fault))

        task_state = server.__getattribute__('OS-EXT-STS:task_state')
        LOG.debug("Current task_state of instance %s is %s" % (instance.name, task_state))
        return task_state != "scheduling"

    def _assign_floating_ips(self, instances):
        for instance in instances:
            node_group = instance.node_group
            if node_group.floating_ip_pool:
                networks.assign_floating_ip(instance.instance_id,
                                            node_group.floating_ip_pool)

    def _await_active(self, cluster, instances):
        """Await all instances are in Active status and available."""
        if not instances:
            return

        active_ids = set()
        while len(active_ids) != len(instances):
            if not g.check_cluster_exists(instances[0].node_group.cluster):
                return
            for instance in instances:
                if instance.id not in active_ids:
                    if self._check_if_active(instance):
                        active_ids.add(instance.id)

            context.sleep(1)

        LOG.info("Cluster '%s': all instances are active" % cluster.id)

    def _check_if_active(self, instance):

        server = nova.get_instance_info(instance)
        if server.status == 'ERROR':
            # TODO(slukjanov): replace with specific error
            raise RuntimeError("node %s has error status with fault: %s" % (server.name, server.fault))

        return server.status == 'ACTIVE'

    def _rollback_cluster_creation(self, cluster, ex):
        """Shutdown all instances and update cluster status."""
        LOG.info("Cluster '%s' creation rollback (reason: %s)",
                 cluster.name, ex)

        self.shutdown_cluster(cluster)

    def _rollback_cluster_scaling(self, cluster, instances, ex):
        """Attempt to rollback cluster scaling."""
        LOG.info("Cluster '%s' scaling rollback (reason: %s)",
                 cluster.name, ex)

        for i in instances:
            self._shutdown_instance(i)

    def _shutdown_instances(self, cluster):
        for node_group in cluster.node_groups:
            for instance in node_group.instances:
                self._shutdown_instance(instance)

    def _shutdown_instance(self, instance):
        ctx = context.ctx()

        if instance.node_group.floating_ip_pool:
            try:
                networks.delete_floating_ip(instance.instance_id)
            except nova_exceptions.NotFound:
                LOG.warn("Attempted to delete non-existent floating IP in "
                         "pool %s from instancie %s",
                         instance.node_group.floating_ip_pool,
                         instance.instance_id)

        try:
            volumes.detach_from_instance(instance)
        except Exception:
            LOG.warn("Detaching volumes from instance %s failed",
                     instance.instance_id)

        try:
            nova.client().servers.delete(instance.instance_id)
        except nova_exceptions.NotFound:
            LOG.warn("Attempted to delete non-existent instance %s",
                     instance.instance_id)

        conductor.instance_remove(ctx, instance)

    def shutdown_cluster(self, cluster):
        """Shutdown specified cluster and all related resources."""
        self._shutdown_instances(cluster)
        self._clean_job_executions(cluster)
