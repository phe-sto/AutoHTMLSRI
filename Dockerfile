FROM alpine:latest
LABEL authors="Phe-sto"

# Install the necessary packages
# g++ produce a smaller image than clang...
RUN apk --no-cache add cmake make g++ curl-dev crypto++-dev tclap-dev

ENV SOURCE_DIR "/usr/src/sri"

# Copy the sources
COPY . ${SOURCE_DIR}

# Go into the sources directory
WORKDIR ${SOURCE_DIR}

# Build the sources with optimizations
RUN mkdir build && cd ${SOURCE_DIR}/build && cmake .. && cmake --build . --target sri CXXFLAGS="-O3"

# Run the executable
# Default command
ENTRYPOINT ["./build/sri"]
# Default arguments that can be overridden
CMD ["--help"]