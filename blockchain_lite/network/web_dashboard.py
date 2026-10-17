"""
Interactive Web Explorer & Live Dashboard (`blockchain_lite/network/web_dashboard.py`).

Features:
- Built strictly with Python 3.11+ Standard Library (`http.server`, `urllib.parse`, `json`, `threading`).
- Zero third-party web frameworks (no Flask, FastAPI, Django, Tornado, aiohttp).
- REST API endpoints for blocks, mempool, wallet balances, transaction history, Merkle proofs, and mining.
- Interactive Single-Page Application with dark glassmorphic design, live blockchain graph,
  wallet management, PoW mining console, and live cryptographic tamper cascade simulator.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import secrets
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from blockchain_lite.crypto.asymmetric import weak_key_warning
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    TX_TYPE_COINBASE,
    BlockchainLiteError,
    HashInterface,
)
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.wallet.wallet import Wallet


HTML_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="api-token" content="__API_TOKEN__">
<title>Blockchain-Lite Ledger & Digital Wallet Explorer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-base: #0a0d14;
    --bg-surface: #111726;
    --bg-card: rgba(22, 30, 49, 0.75);
    --bg-card-hover: rgba(28, 39, 64, 0.85);
    --border-color: rgba(255, 255, 255, 0.08);
    --border-glow: rgba(99, 102, 241, 0.35);
    --primary: #6366f1;
    --primary-light: #818cf8;
    --primary-glow: rgba(99, 102, 241, 0.25);
    --emerald: #10b981;
    --emerald-glow: rgba(16, 185, 129, 0.2);
    --rose: #f43f5e;
    --rose-glow: rgba(244, 63, 94, 0.2);
    --amber: #f59e0b;
    --cyan: #06b6d4;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #8b9bb4;
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --font-mono: 'Fira Code', monospace;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: var(--bg-base);
    background-image: 
      radial-gradient(at 10% 10%, rgba(99, 102, 241, 0.12) 0px, transparent 40%),
      radial-gradient(at 90% 20%, rgba(16, 185, 129, 0.08) 0px, transparent 40%),
      radial-gradient(at 50% 90%, rgba(6, 182, 212, 0.08) 0px, transparent 50%);
    background-attachment: fixed;
    color: var(--text-primary);
    font-family: var(--font-sans);
    line-height: 1.5;
    padding-bottom: 60px;
    min-height: 100vh;
  }

  header {
    border-bottom: 1px solid var(--border-color);
    background: rgba(10, 13, 20, 0.8);
    backdrop-filter: blur(16px);
    position: sticky;
    top: 0;
    z-index: 100;
    padding: 16px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .brand-icon {
    width: 38px;
    height: 38px;
    border-radius: 10px;
    background: linear-gradient(135deg, var(--primary), var(--cyan));
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 19px;
    box-shadow: 0 0 20px var(--primary-glow);
  }

  .brand-title {
    font-size: 19px;
    font-weight: 700;
    letter-spacing: -0.02em;
  }

  .brand-subtitle {
    font-size: 11px;
    color: var(--text-secondary);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .badge {
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    letter-spacing: 0.03em;
  }

  .badge-valid {
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.35);
    color: #34d399;
  }

  .badge-tampered {
    background: rgba(244, 63, 94, 0.15);
    border: 1px solid rgba(244, 63, 94, 0.35);
    color: #fb7185;
  }

  .pulse-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: currentColor;
    display: inline-block;
    box-shadow: 0 0 8px currentColor;
  }

  .container {
    max-width: 1400px;
    margin: 28px auto;
    padding: 0 24px;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }

  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 14px;
    padding: 18px 20px;
    backdrop-filter: blur(12px);
    transition: all 0.2s ease;
  }

  .stat-card:hover {
    border-color: var(--border-glow);
    transform: translateY(-2px);
  }

  .stat-label {
    font-size: 12px;
    color: var(--text-muted);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
  }

  .stat-val {
    font-size: 26px;
    font-weight: 700;
    letter-spacing: -0.02em;
    font-family: var(--font-mono);
  }

  .stat-sub {
    font-size: 11px;
    color: var(--text-secondary);
    margin-top: 4px;
  }

  .nav-tabs {
    display: flex;
    gap: 8px;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 24px;
  }

  .tab-btn {
    background: none;
    border: none;
    color: var(--text-secondary);
    font-family: var(--font-sans);
    font-size: 14px;
    font-weight: 600;
    padding: 12px 20px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
  }

  .tab-btn:hover {
    color: var(--text-primary);
  }

  .tab-btn.active {
    color: var(--primary-light);
    border-bottom-color: var(--primary);
  }

  .panel { display: none; }
  .panel.active { display: block; }

  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 24px;
    backdrop-filter: blur(12px);
    margin-bottom: 24px;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 18px;
  }

  .card-title {
    font-size: 17px;
    font-weight: 700;
    letter-spacing: -0.01em;
  }

  /* Blockchain Graph / Carousel */
  .chain-scroll {
    display: flex;
    gap: 18px;
    overflow-x: auto;
    padding-bottom: 16px;
    scrollbar-width: thin;
    scrollbar-color: var(--border-color) transparent;
  }

  .chain-scroll::-webkit-scrollbar {
    height: 8px;
  }
  .chain-scroll::-webkit-scrollbar-thumb {
    background: var(--border-color);
    border-radius: 4px;
  }

  .block-node {
    min-width: 290px;
    max-width: 290px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 14px;
    padding: 18px;
    flex-shrink: 0;
    position: relative;
    cursor: pointer;
    transition: all 0.25s ease;
  }

  .block-node:hover {
    border-color: var(--primary);
    box-shadow: 0 4px 20px var(--primary-glow);
    transform: translateY(-3px);
  }

  .block-node.active-inspect {
    border-color: var(--cyan);
    box-shadow: 0 0 16px rgba(6, 182, 212, 0.4);
  }

  .block-header-tag {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }

  .block-index {
    font-family: var(--font-mono);
    font-size: 15px;
    font-weight: 700;
    color: var(--cyan);
  }

  .block-prop {
    margin-bottom: 8px;
  }

  .prop-label {
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .prop-val {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .hash-highlight {
    color: var(--text-primary);
    font-weight: 600;
  }

  /* Buttons & Forms */
  .btn {
    background: #4f46e5;  /* 6.3:1 with white text (AA) */
    color: white;
    border: none;
    border-radius: 8px;
    padding: 10px 18px;
    font-size: 13px;
    font-weight: 600;
    font-family: var(--font-sans);
    cursor: pointer;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .btn:hover {
    background: #4338ca;
    box-shadow: 0 0 16px var(--primary-glow);
  }

  .btn-emerald {
    background: #047857;
  }
  .btn-emerald:hover {
    background: #065f46;
    box-shadow: 0 0 16px var(--emerald-glow);
  }

  .btn-rose {
    background: #be123c;
  }
  .btn-rose:hover {
    background: #9f1239;
    box-shadow: 0 0 16px var(--rose-glow);
  }

  .form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 18px;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
  }

  .form-control {
    background: rgba(10, 13, 20, 0.6);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
    color: var(--text-primary);
    font-family: var(--font-sans);
    outline: none;
    transition: border 0.2s;
  }

  .form-control:focus {
    border-color: var(--primary);
  }

  /* Tables */
  .table-responsive {
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  th {
    text-align: left;
    padding: 12px 16px;
    color: var(--text-muted);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--border-color);
  }

  td {
    padding: 14px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    color: var(--text-secondary);
  }

  tr:hover td {
    background: rgba(255, 255, 255, 0.02);
    color: var(--text-primary);
  }

  .code-cell {
    font-family: var(--font-mono);
    font-size: 12px;
  }

  /* Tamper Cascade Visualizer */
  .cascade-step {
    background: rgba(10, 13, 20, 0.5);
    border-left: 3px solid var(--text-muted);
    border-radius: 0 8px 8px 0;
    padding: 12px 18px;
    margin-bottom: 12px;
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .cascade-step.broken {
    border-left-color: var(--rose);
    background: rgba(244, 63, 94, 0.08);
  }

  .cascade-step.ok {
    border-left-color: var(--emerald);
    background: rgba(16, 185, 129, 0.08);
  }

  /* Modal */
  .modal-backdrop {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(8px);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }
  .modal-backdrop.open { display: flex; }

  .modal-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 18px;
    padding: 28px;
    width: 90%;
    max-width: 720px;
    max-height: 85vh;
    overflow-y: auto;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
  }

  .close-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 22px;
    cursor: pointer;
  }
  .close-btn:hover { color: var(--text-primary); }

  /* ---- Accessibility, states & responsive layout (Phase 3) ---- */
  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
  .skip-link {
    position: absolute; left: 12px; top: -48px; z-index: 2000;
    background: var(--primary); color: #fff; padding: 8px 14px; border-radius: 8px;
  }
  .skip-link:focus { top: 12px; }

  :focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
  .form-control:focus-visible { outline: 2px solid var(--cyan); outline-offset: 1px; }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; box-shadow: none; }
  .btn-sm { padding: 6px 10px; font-size: 12px; }
  .btn-row { display: flex; flex-wrap: wrap; gap: 12px; }

  .badge-pending { background: rgba(148, 163, 184, 0.15); border: 1px solid rgba(148, 163, 184, 0.35); color: var(--text-secondary); }
  .badge-info { background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.35); color: #67e8f9; }

  .unit { font-size: 14px; }
  .hint, .muted-sm { font-size: 12px; color: var(--text-muted); }
  .lead { color: var(--text-secondary); font-size: 13px; margin-bottom: 14px; }
  #mempoolHint { margin-bottom: 14px; }
  .accent { color: var(--cyan); }
  .empty { color: var(--text-muted); font-size: 13px; padding: 12px 0; }
  .empty.error, .bad { color: #fb7185; font-weight: 700; }
  .ok-title { color: #34d399; font-size: 14px; margin-bottom: 8px; }
  .bad-title { color: #fb7185; font-size: 14px; margin-bottom: 8px; }
  .sub-title { font-size: 13px; color: var(--text-secondary); margin: 16px 0 8px; }
  .proof-head > div { margin-bottom: 6px; }
  .proof-verdict { margin-top: 10px; }
  .result-area { margin-top: 20px; }
  .form-grid.narrow { max-width: 600px; }
  .balance { font-weight: 700; color: #34d399; }
  .detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 20px; }
  .cascade-step, .code-cell, .prop-val { overflow-wrap: anywhere; }

  /* Block nodes are real buttons (keyboard reachable). */
  button.block-node { font: inherit; color: inherit; text-align: left; display: block; }
  .block-node > span, .block-prop > span { display: block; }
  .block-node > .block-header-tag, .block-node > .block-foot { display: flex; }
  .block-foot { justify-content: space-between; margin-top: 10px; font-size: 11px; color: var(--text-muted); }

  .conn-banner {
    background: rgba(244, 63, 94, 0.15); border-bottom: 1px solid rgba(244, 63, 94, 0.4);
    color: #fecdd3; padding: 10px 28px; font-size: 13px;
  }
  .toast {
    position: fixed; right: 20px; bottom: 20px; z-index: 1500; max-width: min(420px, calc(100vw - 40px));
    padding: 12px 16px; border-radius: 10px; font-size: 13px; background: var(--bg-surface);
    border: 1px solid var(--border-color); box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    opacity: 0; transform: translateY(10px); pointer-events: none;
    transition: opacity 0.2s, transform 0.2s; overflow-wrap: anywhere;
  }
  .toast.show { opacity: 1; transform: none; }
  .toast-ok { border-color: rgba(16, 185, 129, 0.6); }
  .toast-error { border-color: rgba(244, 63, 94, 0.7); color: #fecdd3; }

  .spinner {
    width: 14px; height: 14px; border-radius: 50%; display: inline-block;
    border: 2px solid rgba(255, 255, 255, 0.35); border-top-color: #fff;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 720px) {
    header { flex-wrap: wrap; gap: 10px; padding: 12px 16px; }
    .brand-title { font-size: 16px; }
    .conn-banner { padding: 10px 16px; }
    .container { padding: 0 12px; margin: 16px auto; }
    .stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-bottom: 18px; }
    .stat-card { padding: 12px; }
    .stat-val { font-size: 20px; }
    .nav-tabs { overflow-x: auto; flex-wrap: nowrap; scrollbar-width: none; }
    .tab-btn { white-space: nowrap; padding: 10px 12px; font-size: 13px; }
    .card { padding: 16px; border-radius: 12px; }
    .card-header { flex-wrap: wrap; gap: 8px; }
    .block-node { min-width: 230px; max-width: 230px; }
    .form-grid { grid-template-columns: minmax(0, 1fr); }
    .btn-row .btn, #mineBtn, #sendBtn { width: 100%; justify-content: center; }
    th, td { padding: 10px 10px; }
    .modal-card { width: calc(100% - 24px); padding: 18px; }
    .detail-grid { grid-template-columns: minmax(0, 1fr); }
  }

  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.001ms !important; animation-iteration-count: 1 !important;
      transition-duration: 0.001ms !important; scroll-behavior: auto !important;
    }
    .stat-card:hover, .block-node:hover { transform: none; }
  }
</style>
</head>
<body>

<a class="skip-link" href="#main">Skip to content</a>

<header>
  <div class="brand">
    <div class="brand-icon" aria-hidden="true">&#x26D3;</div>
    <div>
      <h1 class="brand-title">Blockchain-Lite Ledger</h1>
      <div class="brand-subtitle">Interactive Web Explorer &amp; Digital Wallet (educational demo)</div>
    </div>
  </div>
  <div class="header-actions">
    <div id="statusBadge" class="badge badge-pending">
      <span class="pulse-dot" aria-hidden="true"></span> <span id="statusText">LOADING&hellip;</span>
    </div>
    <button type="button" class="btn" onclick="fetchData(true)">&#x21bb; Refresh</button>
  </div>
</header>

<div id="connBanner" class="conn-banner" role="status" hidden></div>
<div id="toast" class="toast" role="status" aria-live="polite" aria-atomic="true"></div>

<main class="container" id="main">
  <!-- Stats Grid -->
  <section class="stats-grid" aria-label="Chain statistics">
    <div class="stat-card">
      <div class="stat-label">Block Height</div>
      <div class="stat-val" id="statHeight">&ndash;</div>
      <div class="stat-sub" id="statTip">Tip: loading&hellip;</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Protocol Difficulty</div>
      <div class="stat-val" id="statDiff">&ndash;</div>
      <div class="stat-sub">Target: leading zero bits</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Circulating Supply</div>
      <div class="stat-val"><span id="statSupply">&ndash;</span> <span class="unit">BCLT</span></div>
      <div class="stat-sub">Derived strictly from UTXO set</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Pending Mempool</div>
      <div class="stat-val" id="statMempool">&ndash;</div>
      <div class="stat-sub">Awaiting block miner inclusion</div>
    </div>
  </section>

  <!-- Tabs Navigation -->
  <div class="nav-tabs" role="tablist" aria-label="Dashboard sections">
    <button type="button" class="tab-btn active" role="tab" id="tabbtn-explorer" data-tab="explorer" aria-controls="tab-explorer" aria-selected="true">&#x1F4DC; Explorer</button>
    <button type="button" class="tab-btn" role="tab" id="tabbtn-wallets" data-tab="wallets" aria-controls="tab-wallets" aria-selected="false" tabindex="-1">&#x1F45B; Wallets &amp; Transfers</button>
    <button type="button" class="tab-btn" role="tab" id="tabbtn-miner" data-tab="miner" aria-controls="tab-miner" aria-selected="false" tabindex="-1">&#x26CF; Mining</button>
    <button type="button" class="tab-btn" role="tab" id="tabbtn-tamper" data-tab="tamper" aria-controls="tab-tamper" aria-selected="false" tabindex="-1">&#x1F6A8; Tamper Lab</button>
  </div>

  <!-- TAB 1: EXPLORER -->
  <section id="tab-explorer" class="panel active" role="tabpanel" aria-labelledby="tabbtn-explorer" tabindex="0">
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">Hash-Linked Blockchain</h2>
        <span class="hint">Select a block to inspect its transactions and Merkle proofs</span>
      </div>
      <div class="chain-scroll" id="chainScroll">
        <p class="empty">Loading chain&hellip;</p>
      </div>
    </div>

    <div class="card" id="blockDetailCard" hidden>
      <div class="card-header">
        <h2 class="card-title" id="detailBlockTitle" tabindex="-1">Block Inspection</h2>
        <button type="button" class="btn btn-sm" onclick="closeBlockDetail()">Close</button>
      </div>
      <div id="blockDetailBody"></div>
    </div>
  </section>

  <!-- TAB 2: WALLETS -->
  <section id="tab-wallets" class="panel" role="tabpanel" aria-labelledby="tabbtn-wallets" tabindex="0" hidden>
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">Demo Wallets</h2>
      </div>
      <div class="table-responsive">
        <table>
          <caption class="sr-only">Demo wallets with addresses and spendable balances</caption>
          <thead>
            <tr>
              <th scope="col">Wallet</th>
              <th scope="col">Address (SHA-256 of public key)</th>
              <th scope="col">Spendable Balance</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody id="walletsTableBody">
            <tr><td colspan="4" class="empty">Loading wallets&hellip;</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2 class="card-title">Send Signed Transaction</h2>
      </div>
      <form id="transferForm">
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label" for="sendSender">Sender Wallet</label>
            <select class="form-control" id="sendSender" required>
              <option value="">Select sender&hellip;</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label" for="sendRecipientSelect">Recipient (pick a demo wallet)</label>
            <select class="form-control" id="sendRecipientSelect">
              <option value="">Choose recipient&hellip;</option>
            </select>
            <label class="form-label" for="sendRecipient">Recipient address (hex, 64 chars)</label>
            <input class="form-control" id="sendRecipient" placeholder="e.g. 3f2a&hellip;" required
                   pattern="[0-9a-fA-F]{64}" autocomplete="off" spellcheck="false">
          </div>
          <div class="form-group">
            <label class="form-label" for="sendAmount">Amount (BCLT)</label>
            <input class="form-control" type="number" id="sendAmount" min="1" step="1" value="10" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="sendFee">Miner Fee (BCLT)</label>
            <input class="form-control" type="number" id="sendFee" min="0" step="1" value="1" required>
          </div>
        </div>
        <button type="submit" class="btn btn-emerald" id="sendBtn">&#x1F4E4; Sign &amp; Broadcast to Mempool</button>
      </form>
    </div>
  </section>

  <!-- TAB 3: MINER -->
  <section id="tab-miner" class="panel" role="tabpanel" aria-labelledby="tabbtn-miner" tabindex="0" hidden>
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">Proof-of-Work Mining</h2>
      </div>
      <p class="lead">
        Mine pending mempool transactions into a new block. The block hash must satisfy
        <code class="code-cell accent">SHA-256(BlockHeader) &lt; 2^(256 - Difficulty)</code>.
      </p>
      <p class="hint" id="mempoolHint"></p>
      <div class="form-grid narrow">
        <div class="form-group">
          <label class="form-label" for="minerSelect">Miner Reward Recipient</label>
          <select class="form-control" id="minerSelect"></select>
        </div>
      </div>
      <button type="button" class="btn btn-emerald" id="mineBtn" onclick="handleMineBlock()">&#x26CF; Mine Next Block</button>
      <div id="miningResult" class="result-area"></div>
    </div>
  </section>

  <!-- TAB 4: TAMPER CASCADE LAB -->
  <section id="tab-tamper" class="panel" role="tabpanel" aria-labelledby="tabbtn-tamper" tabindex="0" hidden>
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">Tamper Cascade Lab (Worklet 3.2 / LOC-2)</h2>
      </div>
      <p class="lead">
        Altering 1 byte of a committed transaction breaks the chain at every layer:
        transaction hash &rarr; RSA signature &rarr; Merkle root &rarr; block PoW hash &rarr; downstream links.
        This is a read-only simulation; the live chain is not modified.
      </p>
      <div class="form-grid narrow">
        <div class="form-group">
          <label class="form-label" for="tamperBlockIdx">Target Block Index</label>
          <input class="form-control" type="number" id="tamperBlockIdx" min="0" step="1" value="1">
        </div>
        <div class="form-group">
          <label class="form-label" for="tamperTxIdx">Target Transaction Index</label>
          <input class="form-control" type="number" id="tamperTxIdx" min="0" step="1" value="0">
        </div>
      </div>
      <div class="btn-row">
        <button type="button" class="btn btn-rose" id="tamperBtn" onclick="handleSimulateTamper()">&#x1F6A8; Simulate 1-Byte Tamper</button>
        <button type="button" class="btn" onclick="clearTamper()">Clear Results</button>
      </div>
      <div id="tamperResults" class="result-area"></div>
    </div>
  </section>
</main>

<!-- Merkle Proof Modal -->
<div class="modal-backdrop" id="merkleModal">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="merkleModalTitle">
    <div class="modal-header">
      <h2 class="card-title" id="merkleModalTitle">&#x1F517; Merkle Inclusion Proof</h2>
      <button type="button" class="close-btn" onclick="closeMerkleModal()" aria-label="Close dialog">&times;</button>
    </div>
    <div id="merkleModalBody" tabindex="0"></div>
  </div>
</div>

<script>
'use strict';
const API_HEADERS = {
  'Content-Type': 'application/json',
  'X-API-Token': document.querySelector('meta[name="api-token"]').content
};
const POLL_MS = 10000;
const TABS = ['explorer', 'wallets', 'miner', 'tamper'];

let chainState = null;
let blocksState = [];
let walletsState = [];
let inspectedIndex = null;
let modalOpener = null;
let toastTimer = null;

// Every server-provided value goes through esc() before it touches innerHTML.
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
function short(hex, n) {
  const s = String(hex ?? '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}
const $ = id => document.getElementById(id);

function toast(message, kind = 'info') {
  const el = $('toast');
  el.textContent = message;
  el.className = 'toast show toast-' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, kind === 'error' ? 8000 : 5000);
}

async function api(path, options) {
  const res = await fetch(path, options);
  let body = null;
  try { body = await res.json(); } catch (_) { /* non-JSON error body */ }
  if (!res.ok || (body && body.ok === false)) {
    throw new Error((body && body.error) || ('HTTP ' + res.status));
  }
  return body;
}
const post = (path, payload) => api(path, { method: 'POST', headers: API_HEADERS, body: JSON.stringify(payload) });

// ---------------------------------------------------------------- tabs
function switchTab(id, moveFocus) {
  TABS.forEach(t => {
    const on = t === id;
    const btn = $('tabbtn-' + t);
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', String(on));
    btn.tabIndex = on ? 0 : -1;
    $('tab-' + t).classList.toggle('active', on);
    $('tab-' + t).hidden = !on;
  });
  // Keep the selected tab visible in the horizontally scrolling strip on phones.
  $('tabbtn-' + id).scrollIntoView({ block: 'nearest', inline: 'nearest' });
  if (moveFocus) $('tabbtn-' + id).focus();
}
document.querySelector('.nav-tabs').addEventListener('click', e => {
  const btn = e.target.closest('[role="tab"]');
  if (btn) switchTab(btn.dataset.tab);
});
document.querySelector('.nav-tabs').addEventListener('keydown', e => {
  const i = TABS.indexOf(document.activeElement.dataset.tab);
  if (i < 0) return;
  const next = { ArrowRight: (i + 1) % TABS.length, ArrowLeft: (i + TABS.length - 1) % TABS.length,
                 Home: 0, End: TABS.length - 1 }[e.key];
  if (next !== undefined) { e.preventDefault(); switchTab(TABS[next], true); }
});

// ---------------------------------------------------------------- data
// Poll /api/chain only; blocks and wallets are re-fetched and re-rendered
// only when the tip changes (balances derive from the UTXO set, i.e. the tip).
async function fetchData(force = false) {
  try {
    const chain = await api('/api/chain');
    const tipChanged = force || !chainState ||
      chain.tip_hash_hex !== chainState.tip_hash_hex || chain.height !== chainState.height;
    if (tipChanged) {
      const [blocks, wallets] = await Promise.all([api('/api/blocks'), api('/api/wallets')]);
      blocksState = blocks;
      walletsState = wallets;
      renderChain();
      renderWallets();
      if (inspectedIndex !== null) showBlockDetail(inspectedIndex, false);
    }
    chainState = chain;
    renderStats();
    setConnection(true);
  } catch (err) {
    setConnection(false, err);
  }
}

function setConnection(ok, err) {
  const banner = $('connBanner');
  if (ok) { banner.hidden = true; return; }
  banner.textContent = 'Cannot reach the ledger server (' + (err && err.message || 'network error') +
    '). Retrying every ' + (POLL_MS / 1000) + ' s.';
  banner.hidden = false;
  if (!chainState) $('chainScroll').innerHTML = '<p class="empty error">Chain data unavailable.</p>';
}

function renderStats() {
  const c = chainState;
  $('statHeight').textContent = c.height;
  $('statTip').textContent = 'Tip: ' + (c.tip_hash_hex ? short(c.tip_hash_hex, 16) : 'none');
  $('statDiff').textContent = c.difficulty;
  $('statSupply').textContent = c.total_supply;
  $('statMempool').textContent = c.mempool_size;
  $('mempoolHint').textContent = c.mempool_size === 0
    ? 'Mempool is empty: mining now creates a block that holds only the coinbase reward.'
    : c.mempool_size + ' pending transaction(s) will be included in the next block.';
  $('statusBadge').className = 'badge ' + (c.is_valid ? 'badge-valid' : 'badge-tampered');
  $('statusText').textContent = c.is_valid ? 'CONSENSUS VALID' : 'CHAIN INVALID';
}

function renderChain() {
  const container = $('chainScroll');
  if (!blocksState.length) {
    container.innerHTML = '<p class="empty">No blocks yet. Create a genesis block to begin.</p>';
    return;
  }
  container.innerHTML = blocksState.map(b => `
    <button type="button" class="block-node${b.index === inspectedIndex ? ' active-inspect' : ''}"
            data-index="${esc(b.index)}" aria-label="Inspect ${b.index === 0 ? 'genesis block' : 'block ' + esc(b.index)}">
      <span class="block-header-tag">
        <span class="block-index">${b.index === 0 ? 'GENESIS' : 'BLOCK #' + esc(b.index)}</span>
        <span class="muted-sm">${esc(b.tx_count)} txs</span>
      </span>
      <span class="block-prop"><span class="prop-label">Block Hash</span>
        <span class="prop-val hash-highlight">${esc(short(b.block_hash_hex, 18))}</span></span>
      <span class="block-prop"><span class="prop-label">Previous Hash</span>
        <span class="prop-val">${esc(short(b.previous_hash_hex, 18))}</span></span>
      <span class="block-prop"><span class="prop-label">Merkle Root</span>
        <span class="prop-val">${esc(short(b.merkle_root_hex, 18))}</span></span>
      <span class="block-foot"><span>Nonce: ${esc(b.nonce)}</span><span>Diff: ${esc(b.difficulty)}</span></span>
    </button>`).join('');
}
$('chainScroll').addEventListener('click', e => {
  const node = e.target.closest('.block-node');
  if (node) showBlockDetail(Number(node.dataset.index), true);
});

function showBlockDetail(idx, moveFocus) {
  const block = blocksState.find(b => b.index === idx);
  if (!block) { closeBlockDetail(); return; }
  inspectedIndex = idx;
  document.querySelectorAll('.block-node').forEach(n =>
    n.classList.toggle('active-inspect', Number(n.dataset.index) === idx));
  $('blockDetailCard').hidden = false;
  $('detailBlockTitle').textContent = `Block #${block.index} (${block.index === 0 ? 'Genesis' : 'Confirmed'})`;

  const rows = block.transactions.map(tx => `
    <tr>
      <td class="code-cell" title="${esc(tx.tx_id)}">${esc(short(tx.tx_id, 16))}</td>
      <td><span class="badge ${tx.tx_type === 'COINBASE' ? 'badge-valid' : 'badge-info'}">${esc(tx.tx_type)}</span></td>
      <td>${esc(tx.total_output_amount)} BCLT</td>
      <td>${esc(tx.inputs.length)} in / ${esc(tx.outputs.length)} out</td>
      <td><button type="button" class="btn btn-sm" data-block="${esc(block.index)}" data-tx="${esc(tx.tx_id)}">&#x1F517; Proof</button></td>
    </tr>`).join('');

  $('blockDetailBody').innerHTML = `
    <div class="detail-grid">
      <div class="cascade-step ok">
        <div><strong>Header Hash:</strong> ${esc(block.block_hash_hex)}</div>
        <div><strong>Merkle Root:</strong> ${esc(block.merkle_root_hex)}</div>
      </div>
      <div class="cascade-step ok">
        <div><strong>Previous Hash:</strong> ${esc(block.previous_hash_hex)}</div>
        <div><strong>Timestamp:</strong> ${esc(new Date(block.timestamp * 1000).toLocaleString())}</div>
      </div>
    </div>
    <div class="table-responsive">
      <table>
        <caption class="sr-only">Transactions in block ${esc(block.index)}</caption>
        <thead><tr><th scope="col">Tx ID (SHA-256)</th><th scope="col">Type</th><th scope="col">Amount</th>
          <th scope="col">Inputs / Outputs</th><th scope="col">Merkle Proof</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  if (moveFocus) $('detailBlockTitle').focus();
}
$('blockDetailBody').addEventListener('click', e => {
  const btn = e.target.closest('button[data-tx]');
  if (btn) viewMerkleProof(Number(btn.dataset.block), btn.dataset.tx, btn);
});

function closeBlockDetail() {
  inspectedIndex = null;
  $('blockDetailCard').hidden = true;
  document.querySelectorAll('.block-node').forEach(n => n.classList.remove('active-inspect'));
}

function renderWallets() {
  const sender = $('sendSender'), recipient = $('sendRecipientSelect'), miner = $('minerSelect');
  const keep = [sender.value, recipient.value, miner.value];

  $('walletsTableBody').innerHTML = walletsState.length
    ? walletsState.map(w => `
      <tr>
        <td><strong>${esc(w.name)}</strong></td>
        <td class="code-cell" title="${esc(w.address)}">${esc(short(w.address, 20))}</td>
        <td class="balance">${esc(w.balance)} BCLT</td>
        <td><button type="button" class="btn btn-sm" data-copy="${esc(w.address)}"
                    aria-label="Copy ${esc(w.name)} address">&#x2398; Copy</button></td>
      </tr>`).join('')
    : '<tr><td colspan="4" class="empty">No wallets registered on this server.</td></tr>';

  const opts = (valueKey, labelFn) => walletsState.map(w =>
    `<option value="${esc(w[valueKey])}">${esc(labelFn(w))}</option>`).join('');
  sender.innerHTML = '<option value="">Select sender…</option>' + opts('name', w => `${w.name} (${w.balance} BCLT)`);
  recipient.innerHTML = '<option value="">Choose recipient…</option>' + opts('address', w => `${w.name} (${short(w.address, 12)})`);
  miner.innerHTML = opts('address', w => `${w.name} (${short(w.address, 12)})`);
  [sender.value, recipient.value, miner.value] = keep;
  if (!miner.value && miner.options.length) miner.selectedIndex = 0;
}
$('walletsTableBody').addEventListener('click', e => {
  const btn = e.target.closest('button[data-copy]');
  if (!btn) return;
  const addr = btn.dataset.copy;
  if (!navigator.clipboard) { toast('Clipboard unavailable; copy the address from the tooltip.', 'error'); return; }
  navigator.clipboard.writeText(addr).then(
    () => toast('Address copied: ' + short(addr, 16), 'ok'),
    () => toast('Copy failed; copy the address from the tooltip.', 'error'));
});
$('sendRecipientSelect').addEventListener('change', e => { $('sendRecipient').value = e.target.value; });

// ---------------------------------------------------------------- actions
$('transferForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('sendBtn');
  const amount = parseInt($('sendAmount').value, 10);
  const fee = parseInt($('sendFee').value, 10);
  btn.disabled = true;
  try {
    const res = await post('/api/transfer', {
      sender_name: $('sendSender').value,
      recipient_address: $('sendRecipient').value.trim(),
      amount, fee
    });
    toast(`Transfer of ${amount} BCLT added to the mempool (tx ${short(res.tx_id, 16)}).`, 'ok');
    fetchData(true);
  } catch (err) {
    toast('Transfer failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

async function handleMineBlock() {
  const btn = $('mineBtn');
  const label = btn.innerHTML;
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Mining… this may take a while';
  $('miningResult').innerHTML = '';
  try {
    const res = await post('/api/mine', { miner_address: $('minerSelect').value });
    $('miningResult').innerHTML = `
      <div class="cascade-step ok">
        <h3 class="ok-title">Block #${esc(res.block.index)} mined</h3>
        <div><strong>Block Hash:</strong> ${esc(res.block.block_hash_hex)}</div>
        <div><strong>Nonce:</strong> ${esc(res.stats.nonce)} | <strong>Hashes:</strong> ${esc(res.stats.hashes_evaluated)}
          | <strong>Speed:</strong> ${esc(Math.round(res.stats.hash_rate))} H/s</div>
      </div>`;
    toast(`Block #${res.block.index} mined.`, 'ok');
    fetchData(true);
  } catch (err) {
    toast('Mining failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.innerHTML = label;
  }
}

async function viewMerkleProof(blockIndex, txId, opener) {
  try {
    const res = await api(`/api/merkle_proof?block=${encodeURIComponent(blockIndex)}&tx_id=${encodeURIComponent(txId)}`);
    const p = res.proof;
    const steps = p.path.length
      ? p.path.map((s, i) => `
          <div class="cascade-step ok">
            <strong>Step ${i + 1}:</strong> sibling on the ${esc(s.direction)} = <span class="code-cell">${esc(s.sibling_hash)}</span>
          </div>`).join('')
      : '<p class="hint">Single-transaction block: the leaf hash is the Merkle root (0 hops).</p>';
    $('merkleModalBody').innerHTML = `
      <div class="proof-head">
        <div><strong>Target Tx ID:</strong> <code class="code-cell">${esc(p.tx_id)}</code></div>
        <div><strong>Block header Merkle root:</strong> <code class="code-cell">${esc(p.merkle_root)}</code></div>
        <div class="proof-verdict"><span class="badge ${p.is_valid ? 'badge-valid' : 'badge-tampered'}">
          ${p.is_valid ? 'Proof verified against block header' : 'Proof does NOT verify'}</span></div>
      </div>
      <h3 class="sub-title">O(log2 N) audit path (${esc(p.path.length)} hops)</h3>
      ${steps}`;
    openModal(opener);
  } catch (err) {
    toast('Could not load Merkle proof: ' + err.message, 'error');
  }
}

// ---------------------------------------------------------------- modal
function openModal(opener) {
  modalOpener = opener || document.activeElement;
  document.querySelector('header').inert = true;
  $('main').inert = true;
  $('merkleModal').classList.add('open');
  document.querySelector('#merkleModal .close-btn').focus();
}
function closeMerkleModal() {
  document.querySelector('header').inert = false;
  $('main').inert = false;
  $('merkleModal').classList.remove('open');
  if (modalOpener && document.contains(modalOpener)) modalOpener.focus();
  modalOpener = null;
}
$('merkleModal').addEventListener('click', e => { if (e.target === $('merkleModal')) closeMerkleModal(); });
document.addEventListener('keydown', e => {
  const modal = $('merkleModal');
  if (!modal.classList.contains('open')) return;
  if (e.key === 'Escape') { e.preventDefault(); closeMerkleModal(); return; }
  if (e.key !== 'Tab') return;
  const items = [...modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')];
  const first = items[0], last = items[items.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});

// ---------------------------------------------------------------- tamper lab
async function handleSimulateTamper() {
  const blockIdx = parseInt($('tamperBlockIdx').value, 10);
  const txIdx = parseInt($('tamperTxIdx').value, 10);
  if (!Number.isInteger(blockIdx) || !Number.isInteger(txIdx) || blockIdx < 0 || txIdx < 0) {
    toast('Enter non-negative whole numbers for block and transaction index.', 'error');
    return;
  }
  const btn = $('tamperBtn');
  btn.disabled = true;
  try {
    const t = (await post('/api/tamper', { block_index: blockIdx, tx_index: txIdx })).report;
    const downstream = t.downstream_broken_block_indices.length
      ? 'Blocks [' + t.downstream_broken_block_indices.map(esc).join(', ') + '] now have broken previous_hash links.'
      : 'This is the tip block, so no downstream blocks exist.';
    $('tamperResults').innerHTML = `
      <div class="cascade-step broken">
        <h3 class="bad-title">Cryptographic cascade failure detected</h3>
        <div><strong>Target:</strong> block #${esc(t.tampered_block_index)}, tx #${esc(t.tampered_tx_index)}</div>
        <div><strong>Original Tx ID:</strong> <span class="code-cell">${esc(t.original_tx_id_hex)}</span></div>
        <div><strong>Tampered Tx ID:</strong> <span class="code-cell bad">${esc(t.tampered_tx_id_hex)}</span></div>
      </div>
      <div class="cascade-step ${t.signature_valid_after_tamper ? 'ok' : 'broken'}">
        <strong>1. Signature check:</strong> ${t.signature_valid_after_tamper
          ? 'still valid (coinbase transactions carry no signature)' : '<span class="bad">INVALID</span>'}
      </div>
      <div class="cascade-step broken">
        <div><strong>2. Merkle root:</strong> <span class="bad">${t.merkle_root_matches_header ? 'unchanged' : 'BROKEN'}</span></div>
        <div>Header: ${esc(t.original_merkle_root_hex)}</div>
        <div>Recomputed: ${esc(t.recomputed_merkle_root_hex)}</div>
      </div>
      <div class="cascade-step broken">
        <div><strong>3. Block PoW hash:</strong> <span class="bad">INVALIDATED</span></div>
        <div>Header hash if Merkle root were updated: ${esc(t.recomputed_block_hash_If_merkle_updated_hex)}</div>
      </div>
      <div class="cascade-step broken"><strong>4. Downstream:</strong> ${downstream}</div>`;
    toast('Tamper simulation complete (live chain unchanged).', 'info');
  } catch (err) {
    toast('Simulation failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}
function clearTamper() { $('tamperResults').innerHTML = ''; }

// ---------------------------------------------------------------- polling
fetchData(true);
setInterval(() => { if (!document.hidden) fetchData(); }, POLL_MS);
document.addEventListener('visibilitychange', () => { if (!document.hidden) fetchData(); });
</script>
</body>
</html>
"""


logger = logging.getLogger(__name__)

MAX_BODY_BYTES: int = 64 * 1024
# Client errors whose message is safe and useful to show (HTTP 400).
_CLIENT_ERRORS = (BlockchainLiteError, ValueError, TypeError)


class _HTTPError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


class _DashboardHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying the shared state the request handlers read."""

    ledger: BlockchainLedger
    named_wallets: Dict[str, Wallet]
    app: "WebDashboardServer"


class WebDashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler serving single-page application & JSON REST APIs."""

    server: _DashboardHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP server access logging to keep console clean."""
        pass

    def do_GET(self) -> None:
        self._guarded(self._route_get)

    def do_POST(self) -> None:
        self._guarded(self._route_post)

    def _guarded(self, route: Any) -> None:
        """Map errors to status codes; never leak unexpected exception text to clients."""
        try:
            route()
        except _HTTPError as exc:
            logger.info("Rejected %s %s: %s", self.command, self.path.split("?")[0], exc.status.value)
            self._send_json({"ok": False, "error": str(exc)}, status=exc.status)
        except _CLIENT_ERRORS as exc:
            logger.info("Rejected %s %s: 400 %s", self.command, self.path.split("?")[0], type(exc).__name__)
            self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception:
            logger.exception("Unhandled error on %s %s", self.command, self.path.split("?")[0])
            self._send_json({"ok": False, "error": "Internal server error"},
                            status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def _route_get(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html", "/explorer"):
            self._send_html(HTML_DASHBOARD.replace("__API_TOKEN__", self.server.app.api_token))
            return

        if path == "/api/chain":
            self._handle_get_chain(query)
            return

        if path == "/api/blocks":
            self._handle_get_blocks()
            return

        if path == "/api/wallets":
            self._handle_get_wallets()
            return

        if path == "/api/merkle_proof":
            self._handle_get_merkle_proof(query)
            return

        self._send_json({"error": "Endpoint not found"}, status=HTTPStatus.NOT_FOUND)

    def _route_post(self) -> None:
        # Server-side signing with custodial keys: every POST needs the per-run token
        # (embedded in the same-origin page; unreadable cross-origin) and a JSON
        # Content-Type, which a cross-site "simple request" cannot send without preflight.
        sent = self.headers.get("X-API-Token", "")
        if not secrets.compare_digest(sent.encode(), self.server.app.api_token.encode()):
            raise _HTTPError(HTTPStatus.UNAUTHORIZED, "Missing or invalid X-API-Token")
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise _HTTPError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json")

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/transfer":
            self._handle_post_transfer(body)
            return

        if path == "/api/mine":
            self._handle_post_mine(body)
            return

        if path == "/api/tamper":
            self._handle_post_tamper(body)
            return

        self._send_json({"error": "Endpoint not found"}, status=HTTPStatus.NOT_FOUND)

    # ------------------------------------------------------------------------
    # API Handlers
    # ------------------------------------------------------------------------

    def _handle_get_chain(self, query: Dict[str, List[str]]) -> None:
        ledger = self.server.ledger
        # Cached per tip; ?full=1 forces full re-validation.
        force = query.get("full", ["0"])[0] == "1"
        report = ledger.validate_full_chain(force=force) if ledger.height > 0 else None
        data = {
            "height": ledger.height,
            "tip_hash_hex": ledger.tip.block_hash_hex if ledger.height > 0 else "",
            "difficulty": ledger.difficulty,
            "block_reward": ledger.block_reward,
            "mempool_size": ledger.mempool_size,
            "total_supply": ledger.total_supply,
            "is_valid": report.is_valid if report else True,
        }
        self._send_json(data)

    def _handle_get_blocks(self) -> None:
        ledger = self.server.ledger
        blocks_data = []
        for block in ledger.blocks:
            txs_data = []
            for tx in block.transactions:
                tx_id = tx.compute_tx_id(ledger.hasher).hex()
                txs_data.append({
                    "tx_id": tx_id,
                    "tx_type": "COINBASE" if tx.tx_type == TX_TYPE_COINBASE else "TRANSFER",
                    "timestamp": tx.timestamp,
                    "inputs": [{"prev_tx_id": i.prev_tx_id.hex(), "output_idx": i.output_index} for i in tx.inputs],
                    "outputs": [{"amount": o.amount, "recipient_address": o.recipient_address.hex()} for o in tx.outputs],
                    "total_output_amount": tx.total_output_amount,
                })
            blocks_data.append({
                "index": block.index,
                "block_hash_hex": block.block_hash_hex,
                "previous_hash_hex": block.previous_hash_hex,
                "merkle_root_hex": block.merkle_root_hex,
                "timestamp": block.timestamp,
                "difficulty": block.difficulty,
                "nonce": block.nonce,
                "tx_count": len(block.transactions),
                "transactions": txs_data,
            })
        self._send_json(blocks_data)

    def _handle_get_wallets(self) -> None:
        ledger = self.server.ledger
        wallets_data = []
        for name, wallet in self.server.named_wallets.items():
            addr = wallet.address.hex()
            bal = ledger.get_balance(wallet.address)
            wallets_data.append({
                "name": name,
                "address": addr,
                "balance": bal,
            })
        self._send_json(wallets_data)

    def _handle_get_merkle_proof(self, query: Dict[str, List[str]]) -> None:
        try:
            b_idx = int(query.get("block", ["0"])[0])
            tx_id_hex = query.get("tx_id", [""])[0]
            tx_id = bytes.fromhex(tx_id_hex)
        except (ValueError, TypeError):
            self._send_json({"ok": False, "error": "Invalid block or tx_id parameter"}, status=HTTPStatus.BAD_REQUEST)
            return

        ledger = self.server.ledger
        proof = ledger.get_merkle_proof(b_idx, tx_id)
        if proof is None:
            self._send_json({"ok": False, "error": "Transaction not found in specified block"}, status=HTTPStatus.NOT_FOUND)
            return

        header_root = ledger.get_block(b_idx).merkle_root
        path_data = [
            {"direction": step.direction, "sibling_hash": step.sibling_hash.hex()}
            for step in proof.steps
        ]
        self._send_json({
            "ok": True,
            "proof": {
                "tx_id": proof.tx_id.hex(),
                "merkle_root": proof.merkle_root.hex(),
                "path": path_data,
                "is_valid": MerkleTree.verify_proof(proof, expected_merkle_root=header_root),
            }
        })

    def _handle_post_transfer(self, body: Dict[str, Any]) -> None:
        sender_name = body.get("sender_name")
        recipient_hex = body.get("recipient_address", "")
        amount = body.get("amount", 0)
        fee = body.get("fee", 0)

        wallet = self.server.named_wallets.get(sender_name) if isinstance(sender_name, str) else None
        if not wallet:
            self._send_json({"ok": False, "error": f"Unknown sender wallet '{sender_name}'"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            recipient_bytes = bytes.fromhex(recipient_hex)
            utxos = self.server.ledger.get_spendable_utxos(wallet.address)
            tx = wallet.create_signed_transfer(
                recipient_address=recipient_bytes,
                amount=amount,
                spendable_utxos=utxos,
                fee=fee,
            )
            self.server.ledger.submit_transaction(tx)
            tx_id = tx.compute_tx_id(self.server.ledger.hasher).hex()
            logger.info("Transfer accepted into mempool tx=%s...", tx_id[:16])
            self._send_json({"ok": True, "tx_id": tx_id})
        except _CLIENT_ERRORS as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def _handle_post_mine(self, body: Dict[str, Any]) -> None:
        miner_hex = body.get("miner_address", "")
        try:
            miner_addr = bytes.fromhex(miner_hex) if miner_hex else None
            new_block, stats = self.server.ledger.mine_pending_transactions(miner_address=miner_addr)
            logger.info("Mined block #%d hash=%s... difficulty=%d hashes=%d in %.2fs",
                        new_block.index, new_block.block_hash_hex[:16], new_block.difficulty,
                        stats.hashes_tried, stats.elapsed_seconds)
            self._send_json({
                "ok": True,
                "block": {
                    "index": new_block.index,
                    "block_hash_hex": new_block.block_hash_hex,
                },
                "stats": {
                    "hashes_evaluated": stats.hashes_tried,
                    "elapsed_seconds": stats.elapsed_seconds,
                    "hash_rate": stats.hashes_per_second,
                    "nonce": stats.winning_nonce,
                }
            })
        except _CLIENT_ERRORS as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def _handle_post_tamper(self, body: Dict[str, Any]) -> None:
        block_idx = body.get("block_index", 0)
        tx_idx = body.get("tx_index", 0)
        try:
            report = self.server.ledger.trace_tamper_cascade(
                tampered_block_index=block_idx,
                tampered_tx_index=tx_idx,
            )
            self._send_json({
                "ok": True,
                "report": {
                    "tampered_block_index": report.tampered_block_index,
                    "tampered_tx_index": report.tampered_tx_index,
                    "original_tx_id_hex": report.original_tx_id_hex,
                    "tampered_tx_id_hex": report.tampered_tx_id_hex,
                    "signature_valid_after_tamper": report.signature_valid_after_tamper,
                    "original_merkle_root_hex": report.original_merkle_root_hex,
                    "recomputed_merkle_root_hex": report.recomputed_merkle_root_hex,
                    "merkle_root_matches_header": report.merkle_root_matches_header,
                    "original_block_hash_hex": report.original_block_hash_hex,
                    "recomputed_block_hash_If_merkle_updated_hex": report.recomputed_block_hash_If_merkle_updated_hex,
                    "downstream_broken_block_indices": list(report.downstream_broken_block_indices),
                }
            })
        except _CLIENT_ERRORS as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    # ------------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------------

    def _read_json_body(self) -> Dict[str, Any]:
        raw_len = self.headers.get("Content-Length", "0").strip()
        if not raw_len.isdigit():  # rejects "", "abc", "-5", "1e3"
            raise _HTTPError(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
        length = int(raw_len)
        if length > MAX_BODY_BYTES:
            self.close_connection = True  # don't read or keep an oversized body
            raise _HTTPError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"Body exceeds {MAX_BODY_BYTES} bytes")
        if length == 0:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _HTTPError(HTTPStatus.BAD_REQUEST, "Body is not valid JSON") from exc
        if not isinstance(body, dict):
            raise _HTTPError(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
        return body

    def _send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WebDashboardServer:
    """Thread-per-request Web Dashboard HTTP Server providing live explorer UI & REST API.

    Ledger state is protected by the ledger's own RLock; every ledger method takes it.
    DEMO ONLY: named wallets' private keys live in this process and POST routes sign
    with them, so POSTs require the per-run `api_token`.
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        named_wallets: Optional[Dict[str, Wallet]] = None,
        host: str = "127.0.0.1",
        port: int = 8080,
        api_token: Optional[str] = None,
    ) -> None:
        self.ledger = ledger
        self.named_wallets = named_wallets or {}
        self.host = host
        self.requested_port = port
        self.bound_port = 0
        self.api_token = api_token or secrets.token_urlsafe(32)
        self._httpd: Optional[_DashboardHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.bound_port}"

    def start(self) -> None:
        if self._httpd is not None:
            return
        handler_cls = WebDashboardHandler
        self._httpd = _DashboardHTTPServer((self.host, self.requested_port), handler_cls)
        # Bind back-references so handler can access ledger and wallets via self.server
        self._httpd.ledger = self.ledger
        self._httpd.named_wallets = self.named_wallets
        self._httpd.app = self
        self.bound_port = self._httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="WebDashboardServer",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> "WebDashboardServer":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


def create_demo_ledger_and_wallets(
    hasher: HashInterface = default_hasher, rsa_bits: int = 384
) -> Tuple[BlockchainLedger, Dict[str, Wallet]]:
    """Initialize a demo chain with Alice, Bob, Charlie, and Miner wallets."""
    ledger = BlockchainLedger(difficulty=4, block_reward=50, hasher=hasher)

    alice = Wallet.generate(label="Alice", bit_length=rsa_bits)
    bob = Wallet.generate(label="Bob", bit_length=rsa_bits)
    charlie = Wallet.generate(label="Charlie", bit_length=rsa_bits)
    miner = Wallet.generate(label="Miner", bit_length=rsa_bits)

    ledger.create_genesis_block(
        initial_allocations=[
            (alice.address, 100),
            (bob.address, 50),
            (charlie.address, 25),
        ],
        timestamp=int(time.time()) - 300,
    )

    # Create one transfer and mine Block #1 for initial demonstration
    alice_utxos = ledger.get_spendable_utxos(alice.address)
    tx1 = alice.create_signed_transfer(
        recipient_address=bob.address,
        amount=20,
        spendable_utxos=alice_utxos,
        fee=2,
    )
    ledger.submit_transaction(tx1)
    ledger.mine_pending_transactions(miner_address=miner.address)

    wallets = {
        "Alice": alice,
        "Bob": bob,
        "Charlie": charlie,
        "Miner": miner,
    }
    return ledger, wallets


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Blockchain-Lite Live Web Dashboard & Explorer")
    parser.add_argument(
        "--host",
        default=os.environ.get("BLOCKCHAIN_LITE_HOST", "127.0.0.1"),
        help="Host interface (default: $BLOCKCHAIN_LITE_HOST or 127.0.0.1)",
    )
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument(
        "--fast-hash",
        action="store_true",
        help="Use the optional hashlib SHA-256 backend (bit-identical; much faster mining)",
    )
    parser.add_argument(
        "--rsa-bits", type=int, default=384,
        help="RSA modulus size for demo wallets (default 384; educational)",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not _is_loopback(args.host):
        print(
            "!" * 78 + "\n"
            f"WARNING: binding to non-loopback host {args.host!r}.\n"
            "This dashboard is a DEMO: wallet private keys live server-side and POST\n"
            "routes sign transactions with them. Anyone holding the API token below can\n"
            "spend the demo wallets. Do not expose it to untrusted networks.\n"
            + "!" * 78,
            file=sys.stderr,
        )

    banner = weak_key_warning(args.rsa_bits)
    if banner:
        print(banner, file=sys.stderr)
    print("[*] Initializing Blockchain-Lite Ledger and demo wallets...")
    hasher: HashInterface = default_hasher
    if args.fast_hash:
        from blockchain_lite.crypto.fast_hash import HashlibSHA256  # opt-in only
        hasher = HashlibSHA256()
    print(f"[*] Hash backend: {type(hasher).__name__}")
    ledger, wallets = create_demo_ledger_and_wallets(hasher=hasher, rsa_bits=args.rsa_bits)

    server = WebDashboardServer(ledger=ledger, named_wallets=wallets, host=args.host, port=args.port)
    server.start()
    logger.info("Dashboard started host=%s port=%d hasher=%s difficulty=%d block_reward=%d wallets=%d",
                args.host, server.bound_port, type(hasher).__name__, ledger.difficulty,
                ledger.block_reward, len(wallets))
    print(f"[+] Blockchain-Lite Web Dashboard is LIVE at: {server.url}")
    print(f"[+] API token for POST routes (X-API-Token; the page sends it automatically): {server.api_token}")
    print("[*] Press Ctrl+C to terminate.")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Web Dashboard...")
        server.stop()
        print("[+] Goodbye!")


if __name__ == "__main__":
    main()
