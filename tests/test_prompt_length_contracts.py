from traigent_schema import SchemaValidator

PROMPT_LIMIT = 10000
SHORT_LIMIT = 1000


def test_agent_prompt_like_fields_enforce_backend_caps():
    validator = SchemaValidator()
    prompt = "x" * (PROMPT_LIMIT + 1)

    errors = validator.validate_json(
        {
            "id": "agent_123",
            "name": "Support Agent",
            "agent_type": "qa",
            "prompt_template": prompt,
        },
        "agent_schema",
    )

    assert errors


def test_agent_short_description_fields_enforce_backend_caps():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "id": "agent_123",
            "name": "Support Agent",
            "agent_type": "qa",
            "description": "x" * (SHORT_LIMIT + 1),
        },
        "agent_schema",
    )

    assert errors


def test_evaluator_judge_config_enforces_prompt_caps():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "name": "Trace Judge",
            "measure_id": "quality",
            "target_type": "observability_trace",
            "judge_config": {
                "instructions": "x" * (PROMPT_LIMIT + 1),
                "model_id": "gpt-4o-mini",
                "context_type": "trace",
            },
        },
        "evaluator_definition_schema",
    )

    assert errors


def test_evaluator_execute_override_judge_config_enforces_prompt_caps():
    validator = SchemaValidator()

    errors = validator.validate_request(
        "/api/v1beta/evaluators/eval_123/execute",
        "POST",
        {
            "target_type": "observability_trace",
            "target_id": "trace_123",
            "override_judge_config": {
                "instructions": "Score trace quality.",
                "model_id": "m" * 101,
                "context_type": "trace",
            },
        },
    )

    assert errors


def test_hybrid_session_create_enforces_prompt_caps():
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        {
            "problem_statement": "x" * (PROMPT_LIMIT + 1),
            "search_space": {"temperature": [0.0, 1.0]},
            "optimization_config": {"max_rounds": 10},
        },
    )

    assert errors
