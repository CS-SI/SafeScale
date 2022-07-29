__Run Integration Tests__

The idea behind integration tests is to run black-box tests against some machines / clusters.

The tests there are also valid go UT -> so some effort was put into preventing someone from accidentally running integration tests with a "go test ./..."

Say you have a tenant, a google one, with name "whatever" in your tenants.toml

In order to run integration test you MUST first place an env variable:<br/>
```export TEST_GCP=whatever```
<br/>then, run:<br/>
```safescaled```
<br/>AND set the tenant yourself, with:
```safescale tenant set whatever```
<br/>(if you set another tenant, tests won't run)

Each provider requires its own exported env var -> for OVH it's TEST_OVH, for flexibleengine -> TEST_FLEXIBLE, etc.

After that, you can run each UT with the CLI or through your IDE, and it will start.
If you fail to do any of the previous steps -> the test is simply skipped

Say you want to run all available tests in a cloud provider.
Say it is OVH.
When the variable TEST_OVH is set, safescaled started and "tenant set" accordingly to TEST_OVH content, go to the directory
```/integrationtests```
and run:
```go test -tags=allintegration -timeout=8h```

if you need a specific subset all you have to do is create a new directory in ```/integrationtests/resources/mysubset```
put the subset there, go in ```/integrationtests``` and run
```go test -tags=integrationtests,subset -timeout=8h```

The main idea for this refactoring is to be able to run parts of Tests when necessary, for example run only Tests about Volume.

To accomplish this, the use of build tags becomes significant, and here is a list of newly introduced ones:
- `integration`: defines we explicitely want to run some integration tests
- `all`: we want to run all tests
- `buckettests`: we want to run bucket tests
- `clustertests`: we want to run cluster tests
- `featuretests`: we want to run features tests
- `hosttests`: (I think the message is passed :-) )
- `networktests`
- `securitygrouptests`
- `sharetests`
- `subnettests`
- `volumetests`
- `labeltests`

Before running the tests, as previously you need to set environment correctly.

To run a test campaign by CLI, you run: (WIP, may change in near future)
```bash
cd integrationtests; go test -tags=allintegration -timeout=8h
````

To run a subset of all the tests, just replace `allintegration` with `integration,<at least one of the previously listed build args>`. Example for networks and subnets only:
```bash
cd integrationtests; go test -tags=integration,networktests,subnettests -timeout=8h
```


___Files organization:___

Internally, the tests are separated in folders representing categories (actually named resources, but this naming may be too restraining, it may evolve), in which you may find:
a file named <folder name>_test.go, which should allow to run tests individually, by adding wanted scenario and running it
at least one file containing scenarios available

___A word about scenarios:___

These are some code that will execute the command sequence to test something, using testing packages.
To be able to run corresponding tests during a complete campaign (with all tests or limited to resources wanted based on previously listed build args), an init function must be defined initialising scenarios to execute (but not starting it; this is the responsibility of run_test.go for a complete campaign).

___A word about provider selection/detection:___

The code is the same for all the providers, there is no code duplication thus reducing risks, the user does not have to define explicitly the driver he wants to test; the driver is detected by intersecting the Cloud Provider defined by `safescale tenant set` and the content of the environment variable.
