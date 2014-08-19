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
from mock import Mock
import unittest2

from sahara.service import retryable_operation as r


class TestRetryable(unittest2.TestCase):
    def test_function_throwing_no_exceptions_succeeds(self):
        #given
        decorator = r.retryable(0, 0)
        func = decorator(lambda x: x)

        #when
        result = func(8)

        #then
        self.assertEquals(result, 8)

    def test_void_function_throwing_no_exceptions_succeeds(self):
        #given
        decorator = r.retryable(0, 0)
        sideefect = []

        def func(sideefect):
            sideefect.append(7)
        func = decorator(func)

        #when
        result = func(sideefect)

        #then
        self.assertEquals(result, None)
        self.assertListEqual(sideefect, [7])

    def test_always_failing_function_is_retried_max_times(self):
        #given
        retry_limit = 7
        decorator = r.retryable(1, 7)

        instance = AlwaysFailingClassWithFailureCounter()
        func = decorator(instance.func)
        caught = None

        #when
        try:
            func()
        except Exception as e:
            caught = e

        #then
        self.assertEquals(type(caught), NotImplementedError)
        self.assertEquals(instance.fail_counter, retry_limit + 1)

    def test_always_failing_function_is_suppressed_after_max_times_with_no_action(self):
        #given
        retry_limit = 7
        decorator = r.retryable(1, retry_limit, None, True)

        instance = AlwaysFailingClassWithFailureCounter()
        func = decorator(instance.func)

        #when
        result = func()

        #then
        self.assertEquals(instance.fail_counter, retry_limit + 1)
        self.assertEquals(result, r.FAILURE_SUPPRESSED)

    def test_action_is_applied_after_failure_suppressed(self):
        #given
        failure_action = Mock()
        decorator = r.retryable(1, 7, failure_action, True)

        instance = AlwaysFailingClassWithFailureCounter()
        func = decorator(instance.func)

        #when
        func()

        #then
        self.assertTrue(failure_action.called)

    def test_validators_are_applied_after_action_executed(self):
        #given
        failure_action = Mock()
        validator = Mock(return_value=True)
        decorator = r.retryable(1, 7, failure_action, True, validator)
        instance = AlwaysFailingClassWithFailureCounter()
        func = decorator(instance.func)

        #when
        func()

        #then
        self.assertTrue(failure_action.called)
        self.assertTrue(validator.called)

    def test_operation_fails_when_validators_fail(self):
        #given
        failure_action = Mock()
        validator = Mock(return_value=False)
        decorator = r.retryable(1, 7, failure_action, True, validator)
        instance = AlwaysFailingClassWithFailureCounter()
        func = decorator(instance.func)

        #when / then
        with self.assertRaises(NotImplementedError):
            func()

    def test_operation_succeeds_after_given_number_of_retries(self):
        #given
        succeed_after = 7
        decorator = r.retryable(1, 10)
        instance = SucceedingAfterNTriesClassWithFailureCounter(succeed_after)
        func = decorator(instance.func)

        #when
        result = func()

        #then
        self.assertEquals(instance.fail_counter, succeed_after - 1)
        self.assertTrue(result)

    def test_on_failure_action_is_applied_after_every_failure(self):
        #given
        retry_limit = 10
        action = Mock()
        decorator = r.retryable(1, retry_limit, action, True)
        instance = AlwaysFailingClassWithFailureCounter()
        func = decorator(instance.func)

        #when
        func()

        #then
        self.assertEquals(action.call_count, retry_limit + 1)

    def test_validators_are_given_all_decorated_function_arguments(self):
        #given
        validator = Mock()
        decorator = r.retryable(0, 0, None, True, validator)
        instance = AlwaysFailingClassWithFailureCounter()
        func = decorator(instance.func)

        #when
        func(1, 2, 3)

        #then
        validator.assert_called_once_with(1, 2, 3)


class AlwaysFailingClassWithFailureCounter(object):
    def __init__(self):
        self.fail_counter = 0

    def func(self, *args, **kwargs):
        self.fail_counter += 1
        raise NotImplementedError()


class SucceedingAfterNTriesClassWithFailureCounter(AlwaysFailingClassWithFailureCounter):
    def __init__(self, succeed_in_n_try):
        super(SucceedingAfterNTriesClassWithFailureCounter, self).__init__()
        self.succeed_in_n_try = succeed_in_n_try

    def func(self, *args, **kwargs):
        if self.fail_counter == self.succeed_in_n_try - 1:
            return True
        super(SucceedingAfterNTriesClassWithFailureCounter, self).func(*args, **kwargs)