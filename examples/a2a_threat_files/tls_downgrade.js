// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Demonstrates malicious A2A agent behavior
// Threat Name: Tool/Protocol Downgrade & TLS Downgrade
// Referenced in a2a_threat_taxonomy.md

// tls_downgrade.js
// Run: node tls_downgrade.js
const express = require('express');
const app = express();
app.get('/agent', (req, res) => {
  res.redirect('http://localhost:8501/agent-plain');
});
app.listen(8500, ()=>console.log('TLS-lie on :8500'));
