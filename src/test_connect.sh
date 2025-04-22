#!/bin/bash
ssh-keygen -R "[127.0.0.1]:2222" 2>/dev/null
ssh -o StrictHostKeyChecking=no -p 2222 user@127.0.0.1