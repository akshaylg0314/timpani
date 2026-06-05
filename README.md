<!--
* SPDX-FileCopyrightText: Copyright 2026 LG Electronics Inc.
* SPDX-License-Identifier: MIT
-->

# timpani

Distributed real-time scheduling system with time-triggered execution capabilities. timpani provides both C and Rust implementations of node executors and schedulers for deterministic real-time applications.

This repository contains both original C implementations and modern Rust ports with enhanced type safety and memory safety.

## Architecture

- **timpani-n(Node Executor)**: Executes time-triggered tasks on individual nodes
- **timpani-o (Node Scheduler)**: Orchestrates and schedules tasks across distributed nodes
- **Sample Applications**: Real-time test applications for system validation

## Getting Started

### Clone the Repository

```bash
git clone --recurse-submodules https://github.com/eclipse-timpani/timpani.git
cd timpani
```

> **Note:** Use `--recurse-submodules` to automatically clone the required submodules (libbpf, etc.).

Refer to the individual component READMEs below for specific build and setup instructions.

## Components

### [Sample Applications](sample-apps/README.md)
Real-time sample applications for real-time system analysis. Provides periodic execution, deadline monitoring, and runtime statistics collection capabilities.

**Quick Build:**
```bash
cd sample-apps
mkdir build && cd build
cmake ..
make
```
*For detailed setup and usage → [Full Documentation](sample-apps/README.md)*

### [timpani-n(Node Executor)](timpani-n/README.md)
C implementation of the time-triggered node executor component.

**Quick Build:**
```bash
cd timpani-n
mkdir build && cd build
cmake ..
make
```

- [CentOS Setup](timpani-n/README.CentOS.md)
- [Ubuntu 20 Setup](timpani-n/README.Ubuntu20.md)

*For detailed setup, dependencies, and usage → [Full Documentation](timpani-n/README.md)*

### [timpani-o (Node Scheduler)](timpani-o/README.md)
C implementation of the orchestrator component with gRPC & protobuf support for distributed scheduling.

**Quick Build:**
```bash
cd timpani-o
mkdir build && cd build
cmake ..
make
```
*For detailed setup, protobuf configuration, and usage → [Full Documentation](timpani-o/README.md)*

### [timpani Rust Components](timpani_rust/README.md)
Rust ports of timpani components with enhanced type safety and memory safety.

#### [Rust timpani-n(Node Executor)](timpani_rust/timpani-n/README.md)
Rust implementation of the node executor with comprehensive CLI interface, configuration validation, and structured logging. **Status**: Configuration parsing complete, runtime features in development.

**Quick Build:**
```bash
cd timpani_rust/timpani-n
cargo build --release
cargo test  # Run tests
```
*For detailed setup, usage examples, and current status → [Full Documentation](timpani_rust/timpani-n/README.md)*

#### [Rust timpani-o (Node Scheduler)](timpani_rust/timpani-o/)
Rust implementation of the global scheduler component. **Status**: In development.

**Quick Build:**
```bash
cd timpani_rust/timpani-o
cargo build --release
cargo test  # Run tests
```
*For detailed setup and current development status → [Full Documentation](timpani_rust/timpani-o/README.md)*

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📖 Documentation Structure

```
timpani/
├── README.md                    # This file - main project overview
├── doc/                         # 📚 Comprehensive documentation
│   ├── README.md               # Documentation guide
│   ├── architecture/           # Architecture documentation
│   │   ├── HLD/               # High-Level Design
│   │   │   ├── timpani_system_design_document.md
│   │   │   └── timpani_rust_grpc_architecture.md
│   │   └── LLD/               # Low-Level Design
│   │       ├── timpani-o/     # Orchestrator components (10 docs)
│   │       └── timpani-n/     # Node executor components (10 docs)
│   ├── features/              # Feature & Requirements
│   │   ├── timpani_features.md
│   │   └── requirements/timpani_requirements.md
│   ├── docs/                  # Implementation guides
│   │   ├── api.md
│   │   ├── getting-started.md
│   │   └── developments.md
│   └── contribution/          # Contribution guidelines
│       ├── coding-rule.md
│       └── guidelines-en.md
├── sample-apps/
│   └── README.md               # Sample applications documentation
├── timpani-n/
│   ├── README.md               # C implementation: Node executor
│   ├── README.CentOS.md       # CentOS setup guide
│   └── README.Ubuntu20.md     # Ubuntu setup guide
├── timpani-o/
│   └── README.md               # C implementation: Node scheduler
└── timpani_rust/
    ├── README.md               # Rust components overview
    ├── timpani-n/
    │   └── README.md           # Rust node executor (config parsing complete)
    └── timpani-o/
        └── README.md           # Rust node scheduler (in development)
```
## How to Get Involved

To contribute to this project, please review the contribution guidelines and join the conversation.
- [Contribution guidelines](doc/contribution/guidelines-en.md)
- [Weekly meeting (Microsoft Teams)](https://teams.microsoft.com/meet/46052781724289?p=v7AILMRZryXY01ApNs)

Meeting minutes and announcements are posted here:
- [Meeting minutes (2026)](https://github.com/eclipse-timpani/timpani/discussions/137)


---

**Navigation:** [Sample Apps](sample-apps/) | [timpani-n(C)](timpani-n/) | [timpani-o (C)](timpani-o/) | [Rust Components](timpani_rust/) | [Rust timpani-n](timpani_rust/timpani-n/)
