# Shieldoo Mesh Admin

[![Build](https://github.com/shieldoo/shieldoo-mesh-admin/actions/workflows/build-release.yml/badge.svg)](https://github.com/shieldoo/shieldoo-mesh-admin/actions/workflows/build-release.yml) 
[![Release](https://img.shields.io/github/v/release/shieldoo/shieldoo-mesh-admin?logo=GitHub&style=flat-square)](https://github.com/shieldoo/shieldoo-mesh-admin/releases/latest) 
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=shieldoo_shieldoo-mesh-admin&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=shieldoo_shieldoo-mesh-admin) 
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=shieldoo_shieldoo-mesh-admin&metric=bugs)](https://sonarcloud.io/summary/new_code?id=shieldoo_shieldoo-mesh-admin) 
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=shieldoo_shieldoo-mesh-admin&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=shieldoo_shieldoo-mesh-admin)

## What is Shieldoo Mesh Admin?

Shieldoo Mesh Admin is a powerful network administration tool based on the open-sourced technology Nebula, which was created at Slack technologies by Nate Brown and Ryan Huber. Nebula powers production networks for millions of users worldwide, and provides a suite of features such as fastest handshakes with a high level of security, automatic detection of the fastest route between hosts, and granular security control.

Shieldoo™️ simplifies the complexity of network security, providing a straightforward and secure way to connect computers and mobile devices. Unlike traditional methods, which require complex tasks like knowing and configuring IP addresses, Shieldoo™️ connects devices in just a few clicks, wherever they are.

## Features of Shieldoo Mesh Admin

- **No Need for Public IP**: Shieldoo™️ removes the need for the complex task of configuring a public IP. It saves time, requires no high-level expertise, and mitigates the vulnerability of your network that comes with making your computer internet-accessible.
  
- **Lighthouse Technology**: Your network has a "lighthouse" that acts as a "signpost". When a node connects to your network, it informs the lighthouse of its location and opens a connection. When your device wants to connect to the server node, it asks the lighthouse where to find it and uses the opened connection.
  
- **Single Sign-On**: Shieldoo™️ allows users to log into the secure network using their Google or Microsoft accounts, providing a seamless login experience without the need for additional credentials.
  
- **Zero Trust**: Shieldoo™️ is built on the Zero Trust principle of never trusting any identity by default. All endpoints on the Shieldoo™️ secure network always require identity verification and checks for service access eligibility.
  
- **Time-limited Access**: Shieldoo™️ supports temporary access privileges, allowing administrators to set time-limited access rights.
  
- **Traffic Monitoring**: The network administrator can check which endpoint connects where and when, allowing full control and the ability to track usage statistics and detect suspicious activity.
  
- **Easy Management**: Shieldoo Mesh Admin is intuitive and simple to use, avoiding complexities like subnet and certificate hassles. The UI is designed with the latest features to offer a top-notch user experience.
  
- **Lightweight Operation**: Shieldoo Mesh Admin doesn't require hefty servers or extensive cloud capacity. Devices can communicate peer-to-peer, interacting with the network backend only for establishing connections and managing security.

## Documentation

Please refer to the [Shieldoo Mesh Admin documentation](https://docs.shieldoo.io/) for more information.

## Build and run

build and run (out folder contains test keys and nebula binaries for linux, archive prototypes for linux/mac/win10)
```
# get dependencies
go get ./...

#build to out folder
go build -o out/shieldoo-mesh-admin ./main

# build docker image
docker build --tag ghcr.io/shieldoo/shieldoo-mesh-admin:latest .
```

## regenerate GQL models

```
go run github.com/99designs/gqlgen
```

# Installation steps

## Install nabula-admin web

Docker deployment expects these configurations in environment variables:
* `SERVER_PORT` - web server port (default is 9000)
* `SERVER_URI` - server URI
* `STORE_HEARTBEATS` - store clients heartbeats to logstore
* `SERVER_JOBAPIKEY` - API key for calling JOBs
* `SERVER_LOGLEVEL` - application log level (default 5)
  * PanicLevel  = 0
  * FatalLevel  = 1
  * ErrorLevel  = 2
  * WarnLevel   = 3
  * InfoLevel   = 4
  * DebugLevel  = 5
  * TraceLevel  = 6
* `OAUTHSERVER_SECRET` - secret for JWT token sha256 generator
* `OAUTHSERVER_DURATION` - doration in seconds for jwt token validity
* `AUTH_LOGINURI` - Login URI (expected `https://YOURDNS/login`)
* `DATABASE_URL` - DB connection string in format: `postgres://<USER>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>`
* `DATABASE_MAXRECORDS` - Max records returned by API to GUI (default is 20)
* `DATABASE_LOG_LOGLEVEL` - database logging level (default is 4)
  * Silent  = 1
  * Error   = 2
  * Warn    = 3
  * Info    = 4
* `DATABASE_LOG_SLOWQUERYMS` - show slow queries when tooks longar that configured time in ms (default 500)
* `DATABASE_LOG_IGNORERECORDNOTFOUND` - true/false if ignore no record found like error (default true)
* `DATABASE_LOG_COLORFUL` - true/false if colorize log output (default false)
* `LIGHTHOUSES_MAXLIGHTHOUSES` - maximum lighthouses per instance
* `LIGHTHOUSES_SECRET` - secret for lighthouses used for technology API authentication

Docker image expecting these mounted volumes (directories):
* `/app/ca` - must contain files `ca.key` and `ca.crt` from nebula CA (deployed via secrets in kubernetes)

After running application for first time please change Public IP and port of your Lighthouse and download configuration files and certificates for lighthouse. You need role ADMINNISTARTOR for this setup process.

