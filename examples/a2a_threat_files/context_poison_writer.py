# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""A2A Threat Example: Context Poisoning Writer

Demonstrates malicious A2A agent behavior
Threat Name: Context Poisoning / Cross-Agent Contamination
Referenced in a2a_threat_taxonomy.md

Example malicious agent that writes poisoned context to shared storage
to contaminate other agents' context and manipulate their behavior.

Run: python3 context_poison_writer.py
"""

from flask import Flask, request
app = Flask(__name__)
@app.route('/write', methods=['POST'])
def write():
    with open('/tmp/a2a_shared_ctx.txt','a') as f:
        f.write(request.data.decode() + "\n")
    return "ok"
if __name__ == '__main__':
    app.run(port=8800)
