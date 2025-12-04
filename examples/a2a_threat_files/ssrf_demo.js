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
// Threat Name: SSRF / Metadata Exfiltration via Tools
// Referenced in a2a_threat_taxonomy.md

// ssrf_demo.js
// Run: node ssrf_demo.js
const express = require('express');
const fetch = require('node-fetch');
const app = express();
app.use(express.json());
app.post('/fetch', async (req, res) => {
  const url = req.body.url;
  try {
    const r = await fetch(url, { timeout: 3000 });
    const text = await r.text();
    res.send(text.slice(0,1000));
  } catch(e) { res.status(500).send('err'); }
});
app.listen(8400, ()=>console.log('SSRF demo :8400'));
