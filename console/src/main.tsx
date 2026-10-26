import React from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

const modules = [
  ['Agent Registry', '待實作：註冊、憑證與健康資訊'],
  ['Evidence & Audit', '待實作：來源驗證、接收確認與資料保留'],
  ['Plugin Catalog', '待實作：簽章與版本管理'],
  ['Connectivity Domains', '待實作：選舉與拓樸觀測']
]

function App() {
  return <main className="shell">
    <header>
      <p className="eyebrow">ALPHA PENTAS · P0</p>
      <h1>Security Assessment Workbench</h1>
      <p className="sub">架構階段 UI 骨架 — 未連接 Agent 或真實資料來源</p>
    </header>
    <section className="cards" aria-label="Planned modules">
      {modules.map(([title, summary]) =>
        <article key={title} className="card">
          <h2>{title}</h2>
          <p>{summary}</p>
          <span className="tag">Planned</span>
        </article>
      )}
    </section>
    <footer>Authorized environments only · No operational controls are enabled.</footer>
  </main>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
