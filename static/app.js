(function () {
  const root = document.body;
  const htmlRoot = document.documentElement;
  const toggle = document.getElementById("theme-toggle");
  const STORAGE_KEY = "bitvault-theme";

  function setTheme(theme) {
    root.setAttribute("data-theme", theme);
    htmlRoot.setAttribute("data-theme", theme);
    localStorage.setItem(STORAGE_KEY, theme);
    if (toggle) {
      toggle.innerHTML = theme === "dark" ? "&#9790;" : "&#9788;";
      toggle.setAttribute(
        "aria-label",
        theme === "dark" ? "Switch to light mode" : "Switch to dark mode",
      );
    }
  }

  const preferred =
    window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  const initialTheme = localStorage.getItem(STORAGE_KEY) || preferred;
  setTheme(initialTheme);

  if (toggle) {
    toggle.addEventListener("click", function () {
      const current = root.getAttribute("data-theme") || "light";
      setTheme(current === "dark" ? "light" : "dark");
    });
  }

  document.querySelectorAll(".share-btn").forEach(function (button) {
    button.addEventListener("click", async function () {
      const url = button.getAttribute("data-share-url");
      if (!url) return;

      if (navigator.share) {
        try {
          await navigator.share({ url: url, title: document.title });
          return;
        } catch (_err) {
          // Fall back to clipboard copy when share modal is canceled.
        }
      }

      try {
        await navigator.clipboard.writeText(url);
        const original = button.textContent;
        button.textContent = "Copied";
        setTimeout(function () {
          button.textContent = original;
        }, 1200);
      } catch (_err) {
        window.prompt("Copy this link:", url);
      }
    });
  });

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
      navigator.serviceWorker.register("/static/sw.js").catch(function () {
        // Ignore registration failure in local/dev environments.
      });
    });
  }
})();
