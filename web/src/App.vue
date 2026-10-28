<template>
  <div class="shell">
    <header class="topbar">
      <div class="container bar">
        <RouterLink to="/" class="brand">
          <span class="logo">SR</span>
          <span class="brand-text">
            <strong>SocradarBot</strong>
            <em>漏洞情报聚合 · 高价值推送</em>
          </span>
        </RouterLink>
        <nav class="nav">
          <RouterLink to="/">情报流</RouterLink>
          <RouterLink to="/templates">模板库</RouterLink>
          <RouterLink to="/settings">配置</RouterLink>
        </nav>
      </div>
    </header>

    <main class="main">
      <div class="container">
        <router-view />
      </div>
    </main>

    <footer class="footer">
      <div class="container">
        SocradarBot · Go 单二进制 · 情报仅用于授权测试与防御研究
      </div>
    </footer>
  </div>
</template>

<style scoped>
.shell { display: flex; flex-direction: column; min-height: 100vh; }
.topbar {
  position: sticky; top: 0; z-index: 40;
  background: linear-gradient(90deg, var(--header), var(--header-2));
  box-shadow: 0 1px 0 rgba(0, 0, 0, 0.08);
}
.bar { display: flex; align-items: center; justify-content: space-between; gap: 18px; height: 62px; }
.brand { display: flex; align-items: center; gap: 11px; color: #fff; }
.brand:hover { color: #fff; }
.logo {
  width: 34px; height: 34px; border-radius: 8px; flex: none;
  display: grid; place-items: center;
  background: #fff;
  color: var(--brand); font-weight: 750; font-size: 13px; letter-spacing: 0.04em;
}
.brand-text { display: flex; flex-direction: column; line-height: 1.2; }
.brand-text strong { font-size: 16px; font-weight: 700; letter-spacing: 0.01em; color: #fff; }
.brand-text em { font-style: normal; font-size: 11px; color: rgba(255, 255, 255, 0.62); margin-top: 3px; }
.nav { display: flex; align-items: center; gap: 4px; }
.nav a {
  color: rgba(255, 255, 255, 0.78); font-size: 13px; font-weight: 550;
  padding: 7px 14px; border-radius: 7px; transition: color 0.15s, background 0.15s;
}
.nav a:hover { color: #fff; background: rgba(255, 255, 255, 0.1); }
.nav a.router-link-active { color: #fff; background: rgba(255, 255, 255, 0.18); }
.main { flex: 1; padding: 24px 0 56px; }
.footer { border-top: 1px solid var(--line); padding: 18px 0 26px; color: var(--dim); font-size: 11.5px; background: #fff; }

@media (max-width: 640px) {
  .bar { height: auto; padding-top: 10px; padding-bottom: 10px; flex-wrap: wrap; gap: 8px; }
  .brand-text em { display: none; }
  .nav { width: 100%; overflow-x: auto; justify-content: flex-start; padding-bottom: 2px; }
  .nav a { padding: 6px 10px; }
  .main { padding: 18px 0 40px; }
}
</style>
