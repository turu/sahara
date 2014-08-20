# Copyright (c) 2014 Piotr Turek
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

import functools
from sahara.openstack.common import log as logging
from random import randrange
import eventlet


LOG = logging.getLogger(__name__)

FAILURE_SUPPRESSED = object()


def retryable(slot_time_ms, retries_limit, on_failure_action=None, suppress_on_limit_exceeded=False, *validators):
    """
    This decorator wraps the underlying function and performs Binary Exponential Backoff algorithm
    (http://en.wikipedia.org/wiki/Exponential_backoff), trying to successfully execute the operation.
    If the number of retries has been exceeded there are two possibilities. Either the whole operation fails explicitly,
    or its failure is suppressed (because this function execution is part of some bigger operation that can
    still succeed, even though this one failed). If that's the case, then a chain of validators is applied to check if
    suppressing failure of this operation can be accepted or not.

    An example of usage would be to apply this decorator to node spawning operation. Under certain circumstances (for
    example OpenStack infrastructure being under heavy load) node spawning can fail if you request several nodes to be
    spawned in a short period of time. If one of the node spawning operations fails, the whole cluster is rollbacked.
    To prevent this from happening, one can apply the Binary Exponential Backoff to the node spawning process, waiting
    until requested resources are available. When the retries limit is exceeded and there still are not enough
    resources to spawn the node, it can be removed from the cluster without the whole operation failing, if and only
    if the offending node was not meant to be the master of the cluster. One can achieve the behavior described above,
    by passing an on_failure_action removing the node from the cluster and a validator checking if cluster's
    topology after the node's been removed, can still be accepted.

    :param slot_time_ms: amount of milliseconds used as the time unit for Binary Exponential Backoff algorithm
    :param retries_limit: max number of retries before failing the operation
    :param suppress_on_limit_exceeded: whether the operation should fail explicitly when retries limit has been exceeded
    :param on_failure_action: action to execute when operation failed and has to be retried
    :returns: result of the wrapped function or FAILURE_SUPPRESSED marker object, if failure has been suppressed
    """

    def decorator(func):
        @functools.wraps(func)
        def handler(*args, **kwargs):
            succeeded, result = _try_execute(*args, **kwargs)
            if succeeded:
                return result
            if retries_limit > 0:
                succeeded, result = _exponential_backoff(*args, **kwargs)
                if succeeded:
                    return result
            return _handle_limit_exceeded(result, *args, **kwargs)

        def _try_execute(*args, **kwargs):
            try:
                return True, func(*args, **kwargs)
            except Exception as e:
                LOG.debug("Execution of operation %s failed with message: %s" % (func.__name__, e.message))
                if on_failure_action:
                    on_failure_action(*args, **kwargs)
                return False, e

        def _exponential_backoff(*args, **kwargs):
            for retry_count in range(1, retries_limit):
                LOG.debug("Retrying (retry count: %s) operation %s" % (retry_count, func.__name__))
                succeeded, result = _try_execute(*args, **kwargs)
                if succeeded:
                    LOG.debug("Execution of operation %s succeeded after %s retries" % (func.__name__, retry_count))
                    return True, result
                _random_sleep(retry_count)
            return _try_execute(*args, **kwargs)

        def _random_sleep(retry_count):
            slots = randrange(2 ** retry_count)
            sleep_in_seconds = float(slots * slot_time_ms) / 1000.
            eventlet.sleep(sleep_in_seconds)

        def _handle_limit_exceeded(last_exception, *args, **kwargs):
            if not suppress_on_limit_exceeded:
                raise last_exception
            if validators:
                LOG.debug("Applying validators %s after suppressed failed execution of operation %s" %
                          (str(validators), func.__name__))
                _apply_validators(last_exception, *args, **kwargs)
            return FAILURE_SUPPRESSED

        def _apply_validators(last_exception, *args, **kwargs):
            for validator in validators:
                if not validator(*args, **kwargs):
                    raise last_exception
        return handler
    return decorator