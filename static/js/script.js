/* TrustLens - theme toggle, upload zones, charts */
(function () {
  "use strict";

  // --- Theme ----------------------------------------------------------------
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-bs-theme", theme);
    var icons = document.querySelectorAll("[data-theme-icon]");
    icons.forEach(function (i) {
      i.classList.toggle("d-none", i.getAttribute("data-theme-icon") !== theme);
    });
    try { localStorage.setItem("trustlens-theme", theme); } catch (e) {}
  }

  var saved = null;
  try { saved = localStorage.getItem("trustlens-theme"); } catch (e) {}
  applyTheme(saved === "light" ? "light" : "dark");

  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-bs-theme");
      applyTheme(cur === "dark" ? "light" : "dark");
    });
  });

  // --- Upload zones -----------------------------------------------------------
  document.querySelectorAll("[data-upload-zone]").forEach(function (zone) {
    var input = document.getElementById(zone.getAttribute("data-upload-zone"));
    if (!input) return;
    var preview = document.getElementById(zone.getAttribute("data-preview"));
    zone.addEventListener("click", function () { input.click(); });
    zone.addEventListener("dragover", function (e) {
      e.preventDefault();
      zone.classList.add("dragover");
    });
    zone.addEventListener("dragleave", function () { zone.classList.remove("dragover"); });
    zone.addEventListener("drop", function (e) {
      e.preventDefault();
      zone.classList.remove("dragover");
      if (e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showPreview(input, preview);
      }
    });
    input.addEventListener("change", function () { showPreview(input, preview); });
  });

  function showPreview(input, preview) {
    if (!preview) return;
    var file = input.files && input.files[0];
    if (!file) { preview.innerHTML = ""; return; }
    var label = document.createElement("div");
    label.className = "mt-2 text-success small";
    if (file.type.indexOf("image/") === 0) {
      var img = document.createElement("img");
      img.src = URL.createObjectURL(file);
      img.className = "img-fluid rounded mt-2";
      img.style.maxHeight = "220px";
      preview.innerHTML = "";
      preview.appendChild(img);
      preview.appendChild(label);
    } else {
      preview.innerHTML = "";
      preview.appendChild(label);
    }
    label.textContent = file.name + " (" + Math.round(file.size / 1024) + " KB) ready";
  }

  // --- Charts (Chart.js) --------------------------------------------------------
  window.trustlensCharts = function (cfg) {
    if (typeof Chart === "undefined") return;
    Object.keys(cfg).forEach(function (id) {
      var el = document.getElementById(id);
      if (!el) return;
      new Chart(el, cfg[id]);
    });
  };

  // --- Password visibility -------------------------------------------------------
  document.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.getElementById(btn.getAttribute("data-toggle-password"));
      if (!target) return;
      var show = target.type === "password";
      target.type = show ? "text" : "password";
      var icon = btn.querySelector("i");
      if (icon) icon.classList.toggle("bi-eye", !show);
      if (icon) icon.classList.toggle("bi-eye-slash", show);
    });
  });

  // --- Auto-dismiss alerts ---------------------------------------------------------
  document.querySelectorAll(".alert-dismissible").forEach(function (a) {
    setTimeout(function () {
      var close = a.querySelector(".btn-close");
      if (close && window.bootstrap) {
        bootstrap.Alert.getOrCreateInstance(a).close();
      }
    }, 7000);
  });
})();
