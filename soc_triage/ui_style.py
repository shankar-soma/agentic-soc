UI_CSS = """
.gradio-container { width: min(1500px, calc(100% - 48px)) !important; max-width: none !important; margin: 0 auto !important; }
.soc-header { padding: 12px 0 18px; border-bottom: 1px solid var(--border-color-primary); }
.soc-header h1 { font-size: 25px; margin: 0 0 4px; font-weight: 650; letter-spacing: -.02em; }
.soc-header p { margin: 0; color: var(--body-text-color-subdued); font-size: 14px; }
.soc-section { margin: 20px 0 10px; }
.soc-section h2 { font-size: 17px; margin: 0 0 3px; font-weight: 650; }
.soc-section p { color: var(--body-text-color-subdued); margin: 0; font-size: 13px; }
.soc-panel { border: 1px solid var(--border-color-primary); border-radius: 8px; background: var(--block-background-fill); padding: 16px; min-height: 240px; }
.soc-panel h3 { font-size: 15px; margin: 0 0 12px; }
.soc-empty { color: var(--body-text-color-subdued); padding: 50px 10px; text-align: center; font-size: 13px; }
.soc-empty strong { display: block; color: var(--body-text-color); font-size: 14px; margin-bottom: 4px; }
.soc-timeline { display: grid; gap: 8px; }
.soc-stage { display: grid; grid-template-columns: 20px 1fr; gap: 10px; padding: 8px 10px; border: 1px solid var(--border-color-primary); border-radius: 7px; }
.soc-stage.pending { opacity: .55; }
.soc-stage.active { border-color: var(--color-accent); background: var(--background-fill-secondary); }
.soc-stage .dot { display: inline-flex; align-items: center; justify-content: center; width: 15px; height: 15px; border-radius: 50%; border: 1px solid var(--body-text-color-subdued); margin-top: 2px; font-size: 11px; }
.soc-stage.done .dot { color: #279476; border-color: #279476; }
.soc-stage.active .dot { border: 2px solid var(--color-accent); border-top-color: transparent; animation: soc-spin .8s linear infinite; }
@keyframes soc-spin { to { transform: rotate(360deg); } }
.soc-stage strong { display: block; font-size: 13px; font-weight: 650; }
.soc-stage small { display: block; font-size: 12px; color: var(--body-text-color-subdued); margin-top: 2px; line-height: 1.4; }
.soc-alert-head { margin-bottom: 14px; }
.soc-alert-head strong { display: block; font-size: 15px; }
.soc-alert-head span { color: var(--body-text-color-subdued); font-size: 11px; }
.soc-timeline-run + .soc-timeline-run { border-top: 1px solid var(--border-color-primary); padding-top: 14px; margin-top: 14px; }
.soc-metrics { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 8px; margin: 12px 0; }
.soc-metric { border: 1px solid var(--border-color-primary); border-radius: 7px; padding: 9px 11px; }
.soc-metric span { display: block; color: var(--body-text-color-subdued); font-size: 11px; }
.soc-metric strong { display: block; font-size: 14px; margin-top: 2px; overflow-wrap: anywhere; }
.soc-route { border-left: 3px solid var(--color-accent); padding: 7px 10px; margin-bottom: 14px; background: var(--background-fill-secondary); font-size: 13px; }
.soc-result-section { border-top: 1px solid var(--border-color-primary); margin-top: 14px; padding-top: 12px; }
.soc-result-section h4 { margin: 0 0 5px; font-size: 13px; }
.soc-result-section p, .soc-result-section li { margin: 0; font-size: 12px; line-height: 1.55; }
.soc-match { border: 1px solid var(--border-color-primary); border-radius: 7px; padding: 9px 11px; margin-top: 8px; }
.soc-match-top { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.soc-match strong { font-size: 13px; }
.soc-match .score, .soc-match summary, .soc-alert-raw summary { color: var(--color-accent); font-size: 11px; cursor: pointer; }
.soc-match .meta { color: var(--body-text-color-subdued); margin-top: 3px; font-size: 11px; }
.soc-match details { border-top: 1px solid var(--border-color-primary); margin-top: 7px; padding-top: 6px; }
.soc-match pre, .soc-alert-raw pre { overflow: auto; max-height: 220px; padding: 8px; background: var(--background-fill-secondary); font-size: 11px; white-space: pre-wrap; overflow-wrap: anywhere; }
.soc-table { border: 1px solid var(--border-color-primary) !important; border-radius: 7px !important; overflow: hidden; }
.soc-review-list { display: grid; gap: 9px; padding: 10px; }
.soc-review-list > p { margin: 6px; color: var(--body-text-color-subdued); font-size: 13px; }
.soc-review-card { border: 1px solid var(--border-color-primary); border-radius: 7px; padding: 11px 13px; background: var(--block-background-fill); min-width: 0; }
.soc-review-head { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 6px 16px; font-size: 13px; }
.soc-review-head span, .soc-review-action { color: var(--body-text-color-subdued); }
.soc-review-action { margin-top: 3px; font-size: 12px; overflow-wrap: anywhere; }
.soc-review-card details { border-top: 1px solid var(--border-color-primary); margin-top: 9px; padding-top: 8px; }
.soc-review-card summary { color: var(--color-accent); cursor: pointer; font-size: 12px; }
.soc-review-card details p, .soc-review-card li { font-size: 12px; line-height: 1.55; overflow-wrap: anywhere; white-space: pre-wrap; }
.soc-review-card details p { margin: 8px 0 0; }
.soc-review-checks { margin-top: 10px; font-size: 12px; }
.soc-review-checks ul { margin: 4px 0 0; padding-left: 20px; }
@media (max-width: 800px) { .gradio-container { width: calc(100% - 24px) !important; } .soc-metrics { grid-template-columns: 1fr; } .soc-panel { min-height: 160px; } }
"""
