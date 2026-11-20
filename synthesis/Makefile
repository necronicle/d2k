CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Werror
TESTS = test_search test_inference test_distinguish test_evidence test_learning test_observation test_tls_observe test_tls_decode test_terminal test_learner test_lower test_joint test_stream test_context test_tracking test_state_question test_continuous test_alternatives test_verification
.PHONY: check clean
TESTS += test_belief
TESTS += test_application_owner
TESTS += test_application_trial
TESTS += test_application_model
TESTS += test_application_https
TESTS += test_application_policy
test_application_policy: application_policy.c application_archive.c application_trial.c application_owner.c raw_tape.c lower.c ../core/plantlv.c tls_decode.c tls_observe.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_policy.c test_application_trial.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include $(filter %.c,$(filter-out test_application_trial.c,$^)) -o $@
test_application_https: application_archive.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_https.c application_model.h application_archive.h
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include application_archive.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_https.c -o $@
TESTS += test_raw_tape
TESTS += test_application_archive
TESTS += test_application_history
test_application_history: application_history.c application_history.h cancel.h test_application_history.c
	$(CC) $(CFLAGS) application_history.c test_application_history.c -o $@
TESTS += test_prefix_refine
TESTS += test_application_refine
TESTS += test_application_late
test_application_late: application_late.c application_late.h test_application_late.c application_model.c ../core/plantlv.c ../core/hello.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include application_late.c application_model.c continuous.c evidence.c distinguish.c verification.c ../core/plantlv.c ../core/hello.c test_application_late.c -o $@
TESTS += test_stream_offset
TESTS += test_prefix_partition
test_prefix_partition: test_prefix_partition.c lower.c lower.h ../core/plantlv.c ../datapath/plan_parse.c ../datapath/plan_apply.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include test_prefix_partition.c lower.c ../core/plantlv.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../core/quic.c ../core/crypto.c ../core/quicwire.c -o $@
test_stream_offset: test_stream_offset.c ../core/plantlv.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/include/d2k_plan.h ../datapath/plan_internal.h
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include test_stream_offset.c ../core/plantlv.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../core/quic.c ../core/crypto.c ../core/quicwire.c -o $@
test_application_refine: application_refine.c application_refine.h prefix_refine.c prefix_refine.h lower.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_refine.c ../core/plantlv.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include application_refine.c prefix_refine.c lower.c ../core/plantlv.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_refine.c -o $@
test_prefix_refine: prefix_refine.c prefix_refine.h test_prefix_refine.c lower.c lower.h ../core/plantlv.c
	$(CC) $(CFLAGS) -I../core/include prefix_refine.c lower.c ../core/plantlv.c test_prefix_refine.c -o $@
test_application_archive: test_application_archive_v2.h application_owner.h ../detect/include/d2k_detect.h application_archive.c application_archive.h application_model.c application_model.h continuous.c evidence.c distinguish.c verification.c test_application_archive.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include application_archive.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_archive.c -o $@
test_raw_tape: raw_tape.c raw_tape.h test_raw_tape.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include raw_tape.c test_raw_tape.c -o $@
TESTS += test_token_content
TESTS += test_cancellation
test_cancellation: test_cancellation.c evidence.c continuous.c alternatives.c distinguish.c tracking.c state_question.c joint.c search.c cancel.h
	$(CC) $(CFLAGS) test_cancellation.c evidence.c continuous.c alternatives.c distinguish.c tracking.c state_question.c joint.c search.c -o $@
test_token_content: token_content.c token_content.h test_token_content.c
	$(CC) $(CFLAGS) -I../core/include token_content.c test_token_content.c -o $@
check: $(TESTS)
	./test_prefix_partition
	./test_cancellation
	./test_token_content
	./test_application_late
	./test_stream_offset
	./test_application_refine
	./test_prefix_refine
	./test_application_archive
	./test_application_history
	./test_raw_tape
	./test_application_model
	./test_application_https
	./test_application_policy
	./test_application_trial
	./test_application_owner
	./test_belief
	./test_search
	./test_inference
	./test_distinguish
	./test_evidence
	./test_learning
	./test_observation
	./test_tls_observe
	./test_tls_decode
	./test_terminal
	./test_learner
	./test_lower
	./test_joint
	./test_stream
	./test_context
	./test_tracking
	./test_state_question
	./test_continuous
	./test_alternatives
	./test_verification
test_search: search.c search.h test_search.c
	$(CC) $(CFLAGS) search.c test_search.c -o $@

test_belief: test_belief.c joint.c joint.h search.c search.h
	$(CC) $(CFLAGS) joint.c search.c test_belief.c -o $@
test_inference: inference.c inference.h test_inference.c
	$(CC) $(CFLAGS) inference.c test_inference.c -o $@
test_distinguish: distinguish.c distinguish.h test_distinguish.c
	$(CC) $(CFLAGS) distinguish.c test_distinguish.c -o $@
clean:
	rm -f $(TESTS)

test_evidence: evidence.c evidence.h distinguish.c distinguish.h test_evidence.c
	$(CC) $(CFLAGS) evidence.c distinguish.c test_evidence.c -o $@

test_learning: evidence.c evidence.h distinguish.c distinguish.h test_learning.c
	$(CC) $(CFLAGS) evidence.c distinguish.c test_learning.c -o $@

test_observation: observation.c observation.h test_observation.c ../detect/include/d2k_detect.h
	$(CC) $(CFLAGS) -I../include -I../core/include -I../detect/include observation.c test_observation.c -o $@

test_tls_observe: tls_observe.c tls_observe.h test_tls_observe.c
	$(CC) $(CFLAGS) tls_observe.c test_tls_observe.c -o $@

test_tls_decode: tls_decode.c tls_decode.h tls_observe.c tls_observe.h experiment.h test_tls_decode.c
	$(CC) $(CFLAGS) -I../core/include -I../detect/include tls_decode.c tls_observe.c test_tls_decode.c -o $@

test_terminal: evidence.c evidence.h distinguish.c distinguish.h test_terminal.c
	$(CC) $(CFLAGS) evidence.c distinguish.c test_terminal.c -o $@

test_learner: learner.c learner.h evidence.c evidence.h distinguish.c distinguish.h test_learner.c
	$(CC) $(CFLAGS) learner.c evidence.c distinguish.c test_learner.c -o $@

test_lower: lower.c lower.h test_lower.c ../core/plantlv.c ../core/include/d2k_plantlv.h
	$(CC) $(CFLAGS) -I../core/include lower.c ../core/plantlv.c test_lower.c -o $@

test_joint: joint.c joint.h search.c search.h learner.c learner.h evidence.c evidence.h distinguish.c distinguish.h lower.c lower.h stream.c stream.h test_joint.c ../core/plantlv.c
	$(CC) $(CFLAGS) -I../core/include -I../detect/include joint.c search.c learner.c evidence.c distinguish.c stream.c lower.c ../core/plantlv.c test_joint.c -o $@

test_stream: stream.c stream.h lower.c lower.h test_stream.c ../core/plantlv.c
	$(CC) $(CFLAGS) -I../core/include -I../detect/include stream.c lower.c ../core/plantlv.c test_stream.c -o $@

test_context: context.c context.h stream.c stream.h lower.c lower.h evidence.c evidence.h distinguish.c distinguish.h test_context.c ../core/plantlv.c
	$(CC) $(CFLAGS) -I../core/include -I../detect/include context.c stream.c lower.c evidence.c distinguish.c ../core/plantlv.c test_context.c -o $@

test_tracking: tracking.c tracking.h evidence.c evidence.h distinguish.h test_tracking.c
	$(CC) $(CFLAGS) tracking.c evidence.c test_tracking.c -o $@

test_state_question: state_question.c state_question.h tracking.c tracking.h distinguish.c distinguish.h test_state_question.c
	$(CC) $(CFLAGS) state_question.c tracking.c distinguish.c test_state_question.c -o $@

test_continuous: continuous.c continuous.h evidence.c evidence.h distinguish.c distinguish.h test_continuous.c
	$(CC) $(CFLAGS) continuous.c evidence.c distinguish.c test_continuous.c -o $@

test_alternatives: alternatives.c alternatives.h evidence.c evidence.h distinguish.c distinguish.h test_alternatives.c
	$(CC) $(CFLAGS) alternatives.c evidence.c distinguish.c test_alternatives.c -o $@

test_verification: verification.c verification.h verification_status.h test_verification.c ../core/include/d2k_sched.h ../core/include/d2k_verdict.h ../core/include/d2k_verify.h
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include verification.c test_verification.c -o $@

test_application_owner: application_owner.c application_owner.h verification.c verification.h test_application_owner.c raw_tls.h tls_decode.c tls_observe.c lower.c ../core/plantlv.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include application_owner.c raw_tape.c lower.c ../core/plantlv.c tls_decode.c tls_observe.c verification.c test_application_owner.c -o $@
test_application_owner: raw_tape.c raw_tape.h

test_application_model: application_model.c application_model.h application_owner.h continuous.c evidence.c distinguish.c verification.c test_application_model.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include application_model.c continuous.c evidence.c distinguish.c verification.c test_application_model.c -o $@

test_application_trial: application_trial.c application_trial.h application_owner.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_trial.c tls_decode.c tls_observe.c lower.c ../core/plantlv.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include application_trial.c application_owner.c raw_tape.c lower.c ../core/plantlv.c tls_decode.c tls_observe.c application_model.c continuous.c evidence.c distinguish.c verification.c test_application_trial.c -o $@
test_application_trial: raw_tape.c raw_tape.h

TESTS += test_prefix_lower
check: test-prefix-lower
.PHONY: test-prefix-lower
test-prefix-lower: test_prefix_lower
	./test_prefix_lower
test_prefix_lower: test_prefix_lower.c prefix_refine.c prefix_refine.h lower.c lower.h ../core/plantlv.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c ../core/quic.c ../core/crypto.c ../core/quicwire.c
	$(CC) $(CFLAGS) -I../core/include -I../datapath/include -o $@ test_prefix_lower.c prefix_refine.c lower.c ../core/plantlv.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c ../core/quic.c ../core/crypto.c ../core/quicwire.c

# Text compiler shares preflight name validation with the datapath parser.
test_application_policy test_application_late test_prefix_partition test_stream_offset test_application_refine test_prefix_refine test_lower test_joint test_stream test_context test_application_owner test_application_trial test_prefix_lower: ../datapath/include/d2k_preflight_plan.h
