#!/usr/bin/env node
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getDocument } from "pdfjs-dist/legacy/build/pdf.mjs";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const { PDFArray, PDFDict, PDFDocument, PDFName, PDFNull, StandardFonts, rgb } = require("pdf-lib");

const STATUS_LABELS = {
  "remediation-required": "Remediation Recommended",
  "remediation-recommended": "Remediation Recommended",
  "remediation-review-recommended": "Review Recommended",
  "needs-review": "Review Recommended",
  "reviewed": "Reviewed",
  "manual": "Manual Validation",
  "informational": "Informational",
  "pass": "Pass",
  "unknown": "Unknown"
};

const SEVERITY_LABELS = {
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info"
};

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 2) {
    args[argv[index].replace(/^--/, "")] = argv[index + 1];
  }
  for (const name of ["scan-json", "base-pdf", "output"]) {
    if (!args[name]) {
      throw new Error(`Missing --${name}`);
    }
  }
  return args;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("\n", " ");
}

function escapeUrl(value) {
  return String(value ?? "").replaceAll('"', "%22").replaceAll("\n", "");
}

function cleanText(value) {
  return String(value ?? "").replace(/\r\n?/g, "\n").trim();
}

function token(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function statusLabel(status) {
  return STATUS_LABELS[status] || status || "";
}

function severityLabel(severity) {
  return SEVERITY_LABELS[severity] || severity || "";
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit"
  });
}

function pointsToInches(points) {
  return `${(Number(points) / 72).toFixed(4)}in`;
}

function reportHref(url) {
  if (!url) return "";
  const value = String(url);
  if (/^(https?:|mailto:|file:)/i.test(value)) return value;
  if (value.startsWith("/")) return `http://127.0.0.1:3100${value}`;
  return value;
}

function countSummary(checks) {
  return checks.reduce((summary, check) => {
    const status = check.status || "unknown";
    summary[status] = (summary[status] || 0) + 1;
    return summary;
  }, {});
}

function isCriticalSnmpUsmLine(lines, index) {
  const line = String(lines[index] || "");
  const previous = String(lines[index - 1] || "");
  const authInline = line.match(/^Authentication Type:\s*(.+)$/i);
  if (authInline?.[1]) return token(authInline[1]) !== "sha512";
  if (/^Authentication Type:\s*$/i.test(previous)) return token(line) !== "sha512";
  const privacyInline = line.match(/^Privacy Type:\s*(.+)$/i);
  if (privacyInline?.[1]) return token(privacyInline[1]) !== "aes256";
  if (/^Privacy Type:\s*$/i.test(previous)) return token(line) !== "aes256";
  return false;
}

function richText(value, context = {}) {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) {
    return value.map((item) => richText(item, context)).filter(Boolean).join("<br>");
  }
  if (typeof value === "object") {
    const link = value._link || value.link;
    if (link?.url) {
      return `<a class="report-link-button" href="${escapeAttr(link.url)}">${escapeHtml(link.label || link.url)}</a>`;
    }
    const text = cleanText(value.label ?? value.value ?? "");
    const tone = value._tone || value.tone;
    const toneClass = tone === "critical" ? " critical-detail" : (tone === "success" ? " positive-detail" : "");
    if (value.multiline || text.includes("\n")) {
      const criticalLines = new Set((value.criticalLines || []).map(String));
      const lines = text.split(/\n/);
      return `<div class="multiline${toneClass}">${lines.map((line, index) => {
        const critical = criticalLines.has(line) || (context.column === "SNMP USM User Details" && isCriticalSnmpUsmLine(lines, index));
        return `<div class="${critical ? "critical-detail" : ""}">${escapeHtml(line)}</div>`;
      }).join("")}</div>`;
    }
    return `<span class="${toneClass.trim()}">${escapeHtml(text)}</span>`;
  }
  return escapeHtml(cleanText(value)).replaceAll("\n", "<br>");
}

function renderDetail(label, value, options = {}) {
  if (!value) return "";
  let content = richText(value);
  if (options.link?.url) {
    const linkLabel = options.link.label || options.link.url;
    const escapedLabel = escapeHtml(linkLabel);
    const anchor = `<a href="${escapeUrl(reportHref(options.link.url))}">${escapedLabel}</a>`;
    content = content.replaceAll(escapedLabel, anchor);
  }
  return `
    <div class="detail-row">
      <dt>${escapeHtml(label)}</dt>
      <dd class="${options.tone === "success" ? "positive-detail" : (options.critical ? "critical-detail" : "")}">${content}</dd>
    </div>
  `;
}

function renderWarning(warning) {
  if (!warning) return "";
  if (Array.isArray(warning)) {
    return warning.map(renderWarning).join("");
  }
  return `<div class="critical-detail warning-block">${richText(warning)}</div>`;
}

function renderDetailRows(rows = []) {
  if (!Array.isArray(rows) || !rows.length) return "";
  return rows.map((row) => {
    let content = escapeHtml(String(row.text ?? row.value ?? ""));
    for (const boldText of row.bold || []) {
      const label = escapeHtml(boldText);
      content = content.replaceAll(label, `<strong>${label}</strong>`);
    }
    for (const link of row.links || []) {
      const label = escapeHtml(link.label || link.url || "");
      const url = reportHref(link.url || "");
      if (label && url) {
        content = content.replaceAll(label, `<a href="${escapeUrl(url)}">${label}</a>`);
      }
    }
    if (Array.isArray(row.bullets) && row.bullets.length) {
      content += `<ul class="detail-bullets">${row.bullets.map((bullet) => `<li>${escapeHtml(bullet)}</li>`).join("")}</ul>`;
    }
    return `
      <div class="detail-row">
        <dt>${escapeHtml(row.label || "Details")}</dt>
        <dd class="${row.tone === "critical" ? "critical-detail" : ""}">${content}</dd>
      </div>
    `;
  }).join("");
}

function renderSpecialConsiderations(special) {
  if (!special?.text) return "";
  let content = escapeHtml(special.text).replaceAll("\n", "<br>");
  if (special.linkLabel && special.image) {
    const label = escapeHtml(special.linkLabel);
    const anchor = `<a href="${escapeUrl(reportHref(special.image))}">${label}</a>`;
    content = content.replaceAll(label, anchor);
  }
  return `
    <div class="detail-row">
      <dt>Special Considerations</dt>
      <dd>${content}</dd>
    </div>
  `;
}

function renderEvidenceTable(table) {
  if (!table) return "";
  const columns = (table.columns || []).filter((column) => column !== "Select");
  if (!columns.length) return "";
  const rows = table.rows || [];
  return `
    <section class="evidence-section">
      ${table.title && table.title !== "Evidence" ? `<h5>${escapeHtml(table.title)}</h5>` : ""}
      <table class="evidence-table">
        <thead>
          <tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr>
        </thead>
        <tbody>
          ${rows.length ? rows.map((row) => `
            <tr>${columns.map((column) => `<td>${richText(row[column], { column })}</td>`).join("")}</tr>
          `).join("") : `<tr><td colspan="${columns.length}">No evidence rows returned.</td></tr>`}
        </tbody>
      </table>
    </section>
  `;
}

function renderCheck(check) {
  const badges = check.hideBadges ? "" : `
    <div class="badge-stack">
      <span class="badge ${escapeAttr(check.status)}">${escapeHtml(statusLabel(check.status))}</span>
      <span class="badge severity-${escapeAttr(check.severity || "medium")}">${escapeHtml(severityLabel(check.severity))}</span>
    </div>
  `;
  const evidenceTables = [
    ...(check.evidenceTable ? [check.evidenceTable] : []),
    ...(check.evidenceTables || [])
  ];
  return `
    <article class="check-card">
      <header class="check-header">
        <h4>${escapeHtml(check.title || "Untitled Check")}</h4>
        ${badges}
      </header>
      ${check.review?.reviewedAt ? `<p class="review-note">Last reviewed and approved by ${escapeHtml(check.review.reviewedBy || "Unknown")} on ${escapeHtml(formatDate(check.review.reviewedAt))}</p>` : ""}
      ${check.change?.changedAt && check.change?.message ? `<p class="change-note">${escapeHtml(check.change.message)} on ${escapeHtml(formatDate(check.change.changedAt))}</p>` : ""}
      <dl class="check-details">
        ${renderDetail("Recommendation", check.recommendation)}
        ${renderWarning(check.recommendationWarning)}
        ${!evidenceTables.length ? renderDetail("Evidence", check.evidence, { tone: check.evidenceTone }) : ""}
        ${renderDetail("Details", check.details, { critical: check.detailTone === "critical", link: check.detailsLink })}
        ${renderWarning(check.detailsWarning)}
        ${renderDetailRows(check.detailRows)}
        ${renderSpecialConsiderations(check.specialConsiderations)}
        ${renderDetail("Guide Section", check.source)}
      </dl>
      ${evidenceTables.map(renderEvidenceTable).join("")}
    </article>
  `;
}

function groupChecks(checks) {
  const groups = new Map();
  for (const check of checks) {
    const category = check.category || "Hardening Checks";
    if (!groups.has(category)) groups.set(category, []);
    groups.get(category).push(check);
  }
  return groups;
}

function reportSections(checks) {
  return [...groupChecks(checks).entries()].map(([category, categoryChecks], categoryIndex) => ({
    id: `report-category-${categoryIndex + 1}`,
    marker: `CPTOC_CATEGORY_${categoryIndex + 1}`,
    title: category,
    checks: categoryChecks.map((check, checkIndex) => ({
      check,
      id: `report-check-${categoryIndex + 1}-${checkIndex + 1}`,
      marker: `CPTOC_CHECK_${categoryIndex + 1}_${checkIndex + 1}`
    }))
  }));
}

function renderToc(sections, pageNumbers = {}) {
  return `
    <section class="table-of-contents">
      <h2>Table of Contents</h2>
      <p class="toc-intro">Select any entry to jump directly to that section.</p>
      <ol class="toc-categories">
        ${sections.map((section) => `
          <li class="toc-category">
            <a href="#${section.id}">
              <span class="toc-label">${escapeHtml(section.title)}</span>
              <span class="toc-leader" aria-hidden="true"></span>
              <span class="toc-page">${escapeHtml(String(pageNumbers[section.marker] || "000"))}</span>
            </a>
            <ol class="toc-checks">
              ${section.checks.map(({ check, id, marker }) => `
                <li>
                  <a href="#${id}">
                    <span class="toc-label">${escapeHtml(check.title || "Untitled Check")}</span>
                    <span class="toc-leader" aria-hidden="true"></span>
                    <span class="toc-page">${escapeHtml(String(pageNumbers[marker] || "000"))}</span>
                  </a>
                </li>
              `).join("")}
            </ol>
          </li>
        `).join("")}
      </ol>
    </section>
  `;
}

function checksByStatuses(checks, statuses) {
  const allowed = new Set(statuses);
  return checks.filter((check) => allowed.has(check.status || "unknown"));
}

function renderSummaryList(checks, emptyText = "None") {
  if (!checks.length) {
    return `<p class="summary-empty">${escapeHtml(emptyText)}</p>`;
  }
  return `
    <ul class="summary-list">
      ${checks.map((check) => `<li>${escapeHtml(check.title || "Untitled Check")}</li>`).join("")}
    </ul>
  `;
}

function renderSummaryCard({ className = "", count, label, checks, emptyText }) {
  return `
    <div class="summary-card ${className}">
      <div class="summary-card-head">
        <strong>${count}</strong>
        <span>${escapeHtml(label)}</span>
      </div>
      ${renderSummaryList(checks, emptyText)}
    </div>
  `;
}

function renderHtml(scan, pageSize, pageNumbers = {}) {
  const checks = scan.checks || [];
  const summary = scan.summary || countSummary(checks);
  const remediationCount = Number(summary["remediation-required"] || 0) + Number(summary["remediation-recommended"] || 0);
  const reviewCount = Number(summary["needs-review"] || 0) + Number(summary["remediation-review-recommended"] || 0);
  const manualCount = Number(summary.manual || 0) + Number(summary.informational || 0);
  const remediationChecks = checksByStatuses(checks, ["remediation-required", "remediation-recommended"]);
  const reviewChecks = checksByStatuses(checks, ["needs-review", "remediation-review-recommended"]);
  const manualChecks = checksByStatuses(checks, ["manual", "informational"]);
  const sections = reportSections(checks);
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Check Point Best Practices Hardening Review</title>
  <style>
    @page { size: ${pointsToInches(pageSize.width)} ${pointsToInches(pageSize.height)}; margin: 0.38in; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: #142033;
      font: 11px/1.42 -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
      background: #ffffff;
    }
    a { color: #d72d67; text-decoration: underline; font-weight: 800; }
    .report-title { margin: 0 0 5px; font-size: 28px; line-height: 1.05; letter-spacing: 0; }
    .report-meta { color: #65758b; font-weight: 700; margin: 0 0 14px; }
    .summary-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin: 14px 0 18px; }
    .summary-card { border: 1px solid #d8e0ea; border-radius: 8px; padding: 11px 14px; background: #f8fafc; break-inside: avoid; }
    .summary-card-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 8px; }
    .summary-remediation { border-color: #f1b3b3; background: #fff1f1; }
    .summary-review { border-color: #ead58d; background: #fff7d6; }
    .summary-reviewed { border-color: #b9e2c8; background: #e8f7ee; }
    .summary-manual { border-color: #d8e0ea; background: #eef3f9; }
    .summary-remediation strong { color: #991b1b; }
    .summary-review strong { color: #8a5a00; }
    .summary-reviewed strong { color: #18794e; }
    .summary-manual strong { color: #40516a; }
    .summary-card strong { display: block; font-size: 24px; line-height: 1; }
    .summary-card span { color: #65758b; font-size: 10px; font-weight: 900; text-transform: uppercase; letter-spacing: .08em; }
    .summary-list { margin: 0; padding: 0 0 0 16px; color: #142033; font-size: 9.6px; line-height: 1.26; }
    .summary-list li { margin: 0 0 2px; break-inside: avoid; }
    .summary-card:first-child .summary-list { columns: 2; column-gap: 18px; }
    .summary-empty { margin: 0; color: #65758b; font-size: 9px; font-weight: 700; }
    .table-of-contents { break-before: page; page-break-before: always; }
    .table-of-contents h2 { margin: 0 0 4px; color: #142033; font-size: 24px; line-height: 1.1; }
    .toc-intro { margin: 0 0 13px; color: #65758b; font-size: 10px; font-weight: 700; }
    .toc-categories, .toc-checks { list-style: none; margin: 0; padding: 0; }
    .toc-category { break-inside: avoid; margin: 0 0 7px; }
    .toc-category > a { color: #142033; font-size: 11px; font-weight: 900; }
    .toc-checks { margin: 3px 0 0 15px; }
    .toc-checks li { break-inside: avoid; margin: 0 0 2px; }
    .toc-checks a { color: #40516a; font-size: 9.5px; font-weight: 700; }
    .table-of-contents a { display: flex; align-items: baseline; gap: 6px; text-decoration: none; }
    .toc-label { min-width: 0; }
    .toc-leader { flex: 1 1 auto; min-width: 16px; border-bottom: 1px dotted #aab5c3; transform: translateY(-2px); }
    .toc-page { flex: 0 0 24px; color: #d72d67; text-align: right; font-variant-numeric: tabular-nums; }
    .toc-marker { position: absolute; color: #ffffff; font-size: 1px; line-height: 1; }
    .category { margin-top: 0; break-before: page; page-break-before: always; break-inside: auto; }
    .category h2 { margin: 0 0 10px; color: #ee0c5d; font-size: 20px; line-height: 1.12; break-after: avoid; }
    .check-card { break-inside: auto; border: 1px solid #d8e0ea; border-radius: 8px; padding: 12px; margin: 0 0 12px; }
    .check-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
    .check-header h4 { margin: 0; font-size: 15px; line-height: 1.18; }
    .badge-stack { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; min-width: 170px; }
    .badge { display: inline-block; border-radius: 999px; padding: 3px 8px; font-size: 9px; font-weight: 900; white-space: nowrap; }
    .remediation-required, .remediation-recommended { color: #991b1b; background: #fee2e2; }
    .remediation-review-recommended, .needs-review { color: #8a5a00; background: #fff2c2; }
    .reviewed, .pass { color: #18794e; background: #dff5e9; }
    .manual, .informational, .unknown { color: #40516a; background: #edf2f7; }
    .severity-high { color: #991b1b; background: #fff1f1; }
    .severity-medium { color: #8a5a00; background: #fff5d6; }
    .severity-low, .severity-info { color: #40516a; background: #edf2f7; }
    .review-note, .change-note { margin: -2px 0 8px; color: #2f7a4f; font-weight: 900; }
    .change-note { margin-top: -5px; }
    .check-details { display: grid; grid-template-columns: 118px minmax(0, 1fr); gap: 6px 10px; margin: 0 0 10px; }
    .detail-row { display: contents; }
    .check-details dt { color: #65758b; font-weight: 900; }
    .check-details dd { margin: 0; overflow-wrap: anywhere; }
    .check-details strong { font-weight: 900; }
    .detail-bullets { margin: 4px 0 0 15px; padding: 0; }
    .detail-bullets li + li { margin-top: 2px; }
    .critical-detail { color: #b42323 !important; font-weight: 900 !important; }
    .positive-detail { color: #18794e !important; font-weight: 900 !important; }
    .warning-block { grid-column: 2; margin: -2px 0 3px; }
    .evidence-section { margin-top: 8px; break-inside: auto; }
    .evidence-section h5 { margin: 9px 0 5px; color: #000000; font-size: 12px; font-weight: 900; }
    .evidence-table { width: 100%; border-collapse: separate; border-spacing: 0; table-layout: fixed; break-inside: auto; }
    .evidence-table thead { display: table-header-group; }
    .evidence-table tr { break-inside: avoid; }
    .evidence-table th { background: #f6f8fb; color: #65758b; font-size: 8px; font-weight: 900; letter-spacing: .08em; text-align: left; text-transform: uppercase; }
    .evidence-table th, .evidence-table td { border-bottom: 1px solid #d8e0ea; padding: 6px 7px; vertical-align: top; overflow-wrap: anywhere; }
    .multiline > div + div { margin-top: 1px; }
    .report-link-button {
      display: inline-block;
      border-radius: 7px;
      padding: 5px 8px;
      background: #e72b66;
      color: #ffffff;
      text-decoration: none;
      font-weight: 900;
    }
  </style>
</head>
<body>
  <h1 class="report-title">Check Point Hardening App - Single Use Public Edition</h1>
  ${scan.reportDomainName ? `<p class="report-meta"><strong>Domain:</strong> ${escapeHtml(scan.reportDomainName)}</p>` : ""}
  <p class="report-meta">Scanned: ${escapeHtml(formatDate(scan.scannedAt))}</p>
  <div class="summary-grid">
    ${renderSummaryCard({ count: checks.length, label: "Checks", checks, emptyText: "No checks returned" })}
    ${renderSummaryCard({ className: "summary-remediation", count: remediationCount, label: "Remediation Recommended", checks: remediationChecks, emptyText: "No remediation recommended" })}
    ${renderSummaryCard({ className: "summary-review", count: reviewCount, label: "Review Recommended", checks: reviewChecks, emptyText: "No review recommended" })}
    ${renderSummaryCard({ className: "summary-manual", count: manualCount, label: "Manual / Informational", checks: manualChecks, emptyText: "No manual or informational checks" })}
  </div>
  ${renderToc(sections, pageNumbers)}
  ${sections.map((section) => `
    <section class="category" id="${section.id}">
      <span class="toc-marker">${section.marker}</span>
      <h2>${escapeHtml(section.title)}</h2>
      ${section.checks.map(({ check, id, marker }) => `
        <div id="${id}">
          <span class="toc-marker">${marker}</span>
          ${renderCheck(check)}
        </div>
      `).join("")}
    </section>
  `).join("")}
</body>
</html>`;
}

async function extractTocPageNumbers(pdfBytes, sections) {
  const markers = sections.flatMap((section) => [section.marker, ...section.checks.map((check) => check.marker)]);
  const remaining = new Set(markers);
  const pageNumbers = {};
  const document = await getDocument({ data: new Uint8Array(pdfBytes), disableWorker: true }).promise;
  try {
    for (let pageNumber = 1; pageNumber <= document.numPages && remaining.size; pageNumber += 1) {
      const page = await document.getPage(pageNumber);
      const content = await page.getTextContent();
      const pageText = content.items.map((item) => item.str || "").join("");
      for (const marker of [...remaining]) {
        if (pageText.includes(marker)) {
          pageNumbers[marker] = pageNumber;
          remaining.delete(marker);
        }
      }
      page.cleanup();
    }
  } finally {
    await document.destroy();
  }
  if (remaining.size) {
    throw new Error(`Could not determine report page numbers for: ${[...remaining].join(", ")}`);
  }
  return pageNumbers;
}

async function renderBodyPdf(scan, outputPath, pageSize) {
  const sections = reportSections(scan.checks || []);
  const chromePaths = [
    process.env.REPORT_CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
  ].filter(Boolean);
  const executablePath = chromePaths.find((path) => existsSync(path));
  const browser = await chromium.launch({
    headless: true,
    ...(executablePath ? { executablePath } : {})
  });
  try {
    const page = await browser.newPage();
    const pdfOptions = {
      width: pointsToInches(pageSize.width),
      height: pointsToInches(pageSize.height),
      printBackground: true,
      preferCSSPageSize: true,
      displayHeaderFooter: true,
      headerTemplate: "<div></div>",
      footerTemplate: `
        <div style="width:100%;font:8px -apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#65758b;padding:0 0.38in;text-align:right;">
          Hardening Review Report - Page <span class="pageNumber"></span>
        </div>
      `,
      margin: {
        top: "0.38in",
        right: "0.38in",
        bottom: "0.42in",
        left: "0.38in"
      }
    };
    await page.setContent(renderHtml(scan, pageSize), { waitUntil: "load" });
    const firstPass = await page.pdf(pdfOptions);
    const pageNumbers = await extractTocPageNumbers(firstPass, sections);
    await page.setContent(renderHtml(scan, pageSize, pageNumbers), { waitUntil: "load" });
    await page.pdf({ ...pdfOptions, path: outputPath });
    return Object.fromEntries(sections.flatMap((section) => [
      [section.id, pageNumbers[section.marker]],
      ...section.checks.map((check) => [check.id, pageNumbers[check.marker]])
    ]));
  } finally {
    await browser.close();
  }
}

function rewriteInternalDestinations(merged, copiedBody, destinations) {
  for (const page of copiedBody) {
    const annotationsValue = page.node.get(PDFName.of("Annots"));
    if (!annotationsValue) continue;
    const annotations = merged.context.lookup(annotationsValue, PDFArray);
    for (let index = 0; index < annotations.size(); index += 1) {
      const annotation = merged.context.lookup(annotations.get(index), PDFDict);
      const destination = annotation.get(PDFName.of("Dest"));
      if (!destination || typeof destination.asString !== "function") continue;
      const destinationId = destination.asString().replace(/^\//, "");
      const bodyPageNumber = Number(destinations[destinationId] || 0);
      const targetPage = copiedBody[bodyPageNumber - 1];
      if (!targetPage) continue;
      const explicitDestination = PDFArray.withContext(merged.context);
      explicitDestination.push(targetPage.ref);
      explicitDestination.push(PDFName.of("XYZ"));
      explicitDestination.push(PDFNull);
      explicitDestination.push(PDFNull);
      explicitDestination.push(PDFNull);
      annotation.set(PDFName.of("Dest"), explicitDestination);
    }
  }
}

function supportedCoverText(font, value) {
  return [...String(value || "")].map((character) => {
    try {
      font.encodeText(character);
      return character;
    } catch {
      return "?";
    }
  }).join("");
}

function fitCoverText(font, value, maxWidth) {
  let text = supportedCoverText(font, value);
  let size = 17;
  while (size > 10 && font.widthOfTextAtSize(text, size) > maxWidth) {
    size -= 0.5;
  }
  if (font.widthOfTextAtSize(text, size) <= maxWidth) return { text, size };
  while (text.length > 4 && font.widthOfTextAtSize(`${text}...`, size) > maxWidth) {
    text = text.slice(0, -1);
  }
  return { text: `${text.trimEnd()}...`, size };
}

async function addReportIdentityToCover(merged, coverPage, customerName, domainName) {
  const name = String(customerName || "").trim();
  const domain = String(domainName || "").trim();
  if (!coverPage || (!name && !domain)) return;
  const font = await merged.embedFont(StandardFonts.HelveticaBold);
  const { width, height } = coverPage.getSize();
  const lines = [
    ...(name ? [`Prepared for: ${name}`] : []),
    ...(domain ? [`Domain: ${domain}`] : [])
  ];
  lines.forEach((line, index) => {
    const fitted = fitCoverText(font, line, width * 0.74);
    const textWidth = font.widthOfTextAtSize(fitted.text, fitted.size);
    coverPage.drawText(fitted.text, {
      x: (width - textWidth) / 2,
      y: height * (0.255 - index * 0.035),
      size: fitted.size,
      font,
      color: rgb(0.08, 0.13, 0.2)
    });
  });
}

async function mergePdfs(basePath, bodyPath, outputPath, destinations = {}, customerName = "", domainName = "") {
  const merged = await PDFDocument.create();
  if (!existsSync(basePath)) {
    throw new Error(`Report cover PDF not found: ${basePath}`);
  }
  const base = await PDFDocument.load(await readFile(basePath), { ignoreEncryption: true });
  const copiedBase = await merged.copyPages(base, base.getPageIndices());
  copiedBase.forEach((page) => merged.addPage(page));
  await addReportIdentityToCover(merged, copiedBase[0], customerName, domainName);
  const body = await PDFDocument.load(await readFile(bodyPath), { ignoreEncryption: true });
  const copiedBody = await merged.copyPages(body, body.getPageIndices());
  copiedBody.forEach((page) => merged.addPage(page));
  rewriteInternalDestinations(merged, copiedBody, destinations);
  await writeFile(outputPath, await merged.save());
}

async function basePageSize(basePath) {
  if (!existsSync(basePath)) {
    throw new Error(`Report cover PDF not found: ${basePath}`);
  }
  const base = await PDFDocument.load(await readFile(basePath), { ignoreEncryption: true });
  const [firstPage] = base.getPages();
  if (!firstPage) {
    return { width: 792, height: 612 };
  }
  const { width, height } = firstPage.getSize();
  return { width, height };
}

async function main() {
  const args = parseArgs(process.argv);
  const scan = JSON.parse(await readFile(args["scan-json"], "utf8"));
  const bodyPath = join(dirname(args.output), "report-body.pdf");
  const pageSize = await basePageSize(args["base-pdf"]);
  const destinations = await renderBodyPdf(scan, bodyPath, pageSize);
  await mergePdfs(args["base-pdf"], bodyPath, args.output, destinations, scan.customerName, scan.reportDomainName);
}

main().catch((error) => {
  console.error(error?.stack || error?.message || error);
  process.exit(1);
});
