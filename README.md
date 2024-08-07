# Auto HTML SRI

SRI provides a powerful defence against code injection, supply chain attacks,
man in the middle and other security risks.

This is a simple tool to generate the SRI hashes of an HTML file and
generates an update HTML.
I.e., you don't need anymore to care and waste time to generate the hash of the resources
during development. Unlike other tools, this one is framework-agnostic.

So far most tools just compute the hash, and you have to manually update the HTML.

There is a dependency with `libcurl4` as the resource can be fetched on web
(a CDN or so).

The tool can be used locally or in your CI/CD pipeline.

## Standard usage:

It is ok so far not to appear smart-enough to read RFCs and be lazy reading a
more convivial one like the one from [MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity).

## execution dependencies:

Dependencies with `libcrypto++8`, and `libcurl4` only are required.

On Debian like distribution, you can install them with:

```bash
sudo apt-get install libcrypto++8 libcurl4
```

## Development dependencies:

Dependencies with `cmake`, `libcrypto++-dev`, `libtclap-dev` and `libcurl-dev` are required.

On Debian like distribution, you can install them with:

```bash
sudo apt-get install cmake libcrypto++-dev libtclap-dev libcurl-dev
```

Plus, of course, a C++ compiler.

## Check dynamically linked libraries:

```bash
ldd <path to executable>
```

## Build:

```bash
cmake CMakelists.txt
```

## Docker

A DockerFile ease the installation of the tool, it only builds the CLI, not the
tests.
You can build the docker image and use the tool with:

```bash
docker build .
docker run <Image ID> test-data/index2.html -a sha512
```

## License

WTFPL, "Choose freedom. Do What The Fuck You Want to" as they say...