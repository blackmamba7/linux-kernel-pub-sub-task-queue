#!/bin/bash

echo -e "INTEGRATION TEST SCRIPTS\n"

./test-scripts/integration-test/delete_op.sh
./test-scripts/integration-test/rename_op.sh
./test-scripts/integration-test/concat_op.sh
./test-scripts/integration-test/stat_op.sh
# [These tests are not deterministic. The random behavior is due to order in which scheduler picks tasks]
#./test-scripts/integration-test/delete_job.sh   
#./test-scripts/integration-test/complete_job.sh
./test-scripts/integration-test/enc_dec_op.sh
./test-scripts/integration-test/hash_op.sh
./test-scripts/integration-test/priority_boost.sh
./test-scripts/integration-test/throttling_users.sh
./test-scripts/integration-test/user_job_access.sh
./test-scripts/integration-test/comp_dec_op.sh

echo -e "UNIT TEST SCRIPTS\n"

./test-scripts/unit-test/delete_op.sh
./test-scripts/unit-test/rename_op.sh
./test-scripts/unit-test/concat_op.sh
./test-scripts/unit-test/stat_op.sh
./test-scripts/unit-test/delete_job.sh
./test-scripts/unit-test/enc_dec_op.sh
./test-scripts/unit-test/hash_op.sh
./test-scripts/unit-test/comp_dec_op.sh
