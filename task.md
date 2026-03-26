Implement the design in docs/mixed-site-execution-design.md. There is no present implmentation of mixed-site execution.

The development of the feature will be considered ready for review once at last the following are present:
* an automated e2e test demonstrating:
    1. startup of a five-component scenario: A -> B -> C -> D -> E plus B -> D plus A -> C. A is in direct, B is in compose, C is in KinD, and D is in VM (use ubuntu-24.04-minimal-cloudimg-arm64.img), and E is compose. this should show startup in waves, as specified in the doc. for example, in this case the startup order must be E then D then C then B then A
    2. demonstration of connectivity along all routes (AB, BC, CD, BD)
    3. demonstration of non-connectivity in the most adversarial of cases (e.g., trying to gain access via the host)
    4. assertion of correctness of run and state files
    5. assertion of correctness of manager managed state
    6. clean teardown of the scenario
    * this needs to work on linux and locally on macos
* an automated e2e test demonstrating daemonization of `amber run` and subsequent ability to stop
* automated e2e tests demonstrating observability for both the scenario and the manager
* an automated e2e test demonstrating robustness in failure cases, including but not limited to:
    - partial site failure during launch (the scenario should not begin and instead tear down cleanly)
    - cleanup after coordinator dies during setup
    - component failure in a site after setup has completed (the site manager should bring the components back up)
    - site failure after setup has completed (the site manager should bring the site back up; particularly for direct/vm sinc k8s and compose have restart mechanisms built in)
    - a site becomes temporarily unreachable
* the automated e2e tests run in CI
* an example demonstrating mixed-site execution in a user-friendly way, and not just a shitty reiteration of the smoke test commands
* the code follows the code style and maintainability guidelines

You must finish all of these before returning, or otherwise explain in detail why the request was infeasible.

Ensure to write simple, maintainable code. Aggressively deduplicate logic and hoist reasonably shared code into the trunk of the compiler. This is a security sensitive tool, so simple = auditable = secure. No not write excessively complex code or stupidly defensive code that is defensive due to ignorance of how things work and what invariants hold. Write efficient, maintainable, idiomatic Rust.
