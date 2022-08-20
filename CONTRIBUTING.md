## Running tests

Before running tests, build the integration test base image first. Do this every time you've modified the sources.

~~~bash
make integration-test-base
~~~

Then:

~~~bash
cargo test
~~~
