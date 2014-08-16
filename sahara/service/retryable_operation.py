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
from random import randrange
import eventlet

FAILURE_SUPPRESSED = object()


def retryable(slot_time_ms, retries_limit, suppress_on_limit_exceeded=False, failure_suppressed_action=None,
              *validators):
    """
    This decorator wraps the underlying function and performs Binary Exponential Backoff algorithm
    (http://en.wikipedia.org/wiki/Exponential_backoff), trying to successfully execute the operation.
    If the number of retries has been exceeded there are two possibilities. Either the whole operation fails explicitly,
    or its failure is suppressed (because this function execution is part of some bigger operation that can
    still succeed, even though this one failed). If that's the case, then the failure_suppressed_action is performed,
    possibly changing some internal state of the calling object and a chain of validators is applied to check if
    suppressing failure of this operation can be accepted or not.

    An example of usage would be to apply this decorator to node spawning operation. Under certain circumstances (for
    example OpenStack infrastructure being under heavy load) node spawning can fail if you request several nodes to be
    spawned in a short period of time. If one of the node spawning operations fails, the whole cluster is rollbacked.
    To prevent this from happening, one can apply the Binary Exponential Backoff to the node spawning process, waiting
    until requested resources are available. When the retries limit is exceeded and there still are not enough
    resources to spawn the node, it can be removed from the cluster without the whole operation failing, if and only
    if the offending node was not meant to be the master of the cluster. One can achieve the behavior described above,
    by passing an failure_suppressed_action removing the node from the cluster and a validator checking if cluster's
    topology after the node's been removed, can still be accepted.

    :param slot_time_ms: amount of milliseconds used as the time unit for Binary Exponential Backoff algorithm
    :param retries_limit: max number of retries before failing the operation
    :param suppress_on_limit_exceeded: whether the operation should fail explicitly when retries limit has been exceeded
    :param failure_suppressed_action: action to execute when suppress_on_limit_exceeded set to true
    :param validators: chain of validators to apply after failure_suppressed_action has been executed

    :returns: result of the wrapped function
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
            return _handle_limit_exceeded(result)

        def _try_execute(*args, **kwargs):
            try:
                return True, func(*args, **kwargs)
            except Exception as e:
                return False, e

        def _exponential_backoff(*args, **kwargs):
            for retry_count in range(1, retries_limit):
                succeeded, result = _try_execute(*args, **kwargs)
                if succeeded:
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
            if failure_suppressed_action:
                failure_suppressed_action(*args, **kwargs)
            if validators:
                _apply_validators(last_exception, *args, **kwargs)
            return FAILURE_SUPPRESSED

        def _apply_validators(last_exception, *args, **kwargs):
            for validator in validators:
                if not validator(*args, **kwargs):
                    raise last_exception
        return handler
    return decorator