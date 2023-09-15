# Vulnerability Lookup Service API

The **Vulnerability Lookup Service API** (VLS-API) is a go-lang based API, to get Vulnerabilities associated with the packages used in different programming languages. VLS-API supports multiple ecosystems for detecting vulnerabilities in packages.

## Features
 - Fetches the latest vulnerabilities data from [Open Source Vulnerability Database](https://github.com/google/osv.dev).
 - Supports searching for vulnerabilities associated with specific packages. 
 - Supports multiple package scan.
 - Ecosystem Supports: **PyPI, NPM, Maven, crates.io/Rust, Go**
 - Easy to integrate with other applications & services.
 - Fast and Efficient performance.

## Build

It is recommended to run the VLS-API as a docker container. To build and run the VLS-API, follow these steps

1. We have a docker file, build a docker image using:
    ```docker
    docker build -t iss-lab/vls-api .
    ```

2. Start the docker container :
    ```docker
    docker run --rm -d -p 3000:3000 iss-lab/vls-api
    ```

**Note** : The vls-api can be accessed via url `http://localhost:3000/`

## API Endpoints

The API provides the following endpoints:

### 1. POST  ***/scan***

- The request sent to `/scan` returns the Summary, Description and Severity of the vulnerabilities existing in the package. An attribute `overallSeverity` gives a summary of the severity of the package, based upon the severities of different vulnerabilities that exist in a package for it's specific version.

#### 1.1 Request - Body

The request is sent in form of JSON, which is as follows:

```json
{
    "scan_request": [
        {
            "version":"",   // Version of package to be scanned
            "name": "",     // Name of package to be scanned
            "ecosystem": "" // Ecosystem of package to be scanned (e.g. PyPI, Maven, Go, etc.)
        }
    ]
}
```

### 2. GET  ***/health***

This endpoint is used to check whether the API is alive or not. 


