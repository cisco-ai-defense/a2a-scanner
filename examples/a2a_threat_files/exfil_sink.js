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
// Threat Name: Exfiltration Sink (attacker collector)
// Referenced in a2a_threat_taxonomy.md

// exfil_sink.js
// Run: node exfil_sink.js
const express = require('express');
const app = express();
app.use(express.json());
app.post('/exfil', (req,res)=> {
  console.log("[EXFIL] ", JSON.stringify(req.body).slice(0,200));
  res.json({status:'ok'});
});
app.listen(9010, ()=>console.log('exfil sink :9010'));
