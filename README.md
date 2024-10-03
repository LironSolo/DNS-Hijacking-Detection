
DNS Hijacking Detection and Response Traffic Simulator
Overview
This script provides tools for both detecting DNS hijacking attacks and simulating DNS TXT response packets for testing purposes. It analyzes DNS traffic in real-time, flags potentially suspicious domains, and retrieves domain reports from VirusTotal. Additionally, the script allows for the crafting and sending of custom or random DNS TXT response packets, which could be used in penetration testing or to simulate attack scenarios.

Features
DNS Hijacking Detection: The script captures DNS response packets, specifically those containing TXT records, and analyzes them for suspicious content, such as encoded commands or Base64-encoded data.

VirusTotal Domain Report: It integrates with the VirusTotal API to fetch domain reports and provides detailed information about flagged domains.

DNS Response Traffic Simulator: You can simulate sending DNS TXT response packets with custom or random suspicious content, replicating common DNS hijacking attack methods.
