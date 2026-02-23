"use strict";

window.Blocks = window.Blocks || {};

window.Blocks.initSessionTimeout = function (options) {
    if (!options) {
        return;
    }

    var idleSeconds = Number(options.idleSeconds) || 10800;
    var warnWindow = Number(options.warnSeconds) || 300;
    var warnAfter = Math.max(0, idleSeconds - warnWindow);
    var lastActivity = Date.now();
    var warnTimer = null;
    var logoutTimer = null;
    var countdownTimer = null;

    var backdrop = document.getElementById("session-timeout-backdrop");
    var countdownEl = document.getElementById("session-timeout-countdown");
    var stayButton = document.getElementById("session-timeout-stay");
    var logoutButton = document.getElementById("session-timeout-logout");

    if (!backdrop || !countdownEl || !stayButton || !logoutButton) {
        return;
    }

    function formatSeconds(value) {
        var total = Math.max(0, Math.floor(value));
        var minutes = Math.floor(total / 60);
        var seconds = total % 60;
        return minutes + ":" + String(seconds).padStart(2, "0");
    }

    function resetTimers() {
        if (warnTimer) {
            clearTimeout(warnTimer);
        }
        warnTimer = setTimeout(showWarning, warnAfter * 1000);
    }

    function updateCountdown(secondsLeft) {
        if (countdownEl) {
            countdownEl.textContent = formatSeconds(secondsLeft);
        }
    }

    function showWarning() {
        backdrop.classList.add("is-open");
        backdrop.setAttribute("aria-hidden", "false");
        var remaining = warnWindow;
        updateCountdown(remaining);
        if (countdownTimer) {
            clearInterval(countdownTimer);
        }
        countdownTimer = setInterval(function () {
            remaining -= 1;
            updateCountdown(remaining);
            if (remaining <= 0) {
                clearInterval(countdownTimer);
            }
        }, 1000);
        if (logoutTimer) {
            clearTimeout(logoutTimer);
        }
        logoutTimer = setTimeout(forceLogout, warnWindow * 1000);
    }

    function hideWarning() {
        backdrop.classList.remove("is-open");
        backdrop.setAttribute("aria-hidden", "true");
        if (logoutTimer) {
            clearTimeout(logoutTimer);
            logoutTimer = null;
        }
        if (countdownTimer) {
            clearInterval(countdownTimer);
            countdownTimer = null;
        }
    }

    function forceLogout() {
        var headers = {
            "Content-Type": "application/json"
        };
        if (window.getCSRFToken) {
            var csrfToken = window.getCSRFToken();
            if (csrfToken) {
                headers["X-CSRF-Token"] = csrfToken;
            }
        }
        fetch("/logout", {
            method: "POST",
            headers: headers
        }).finally(function () {
            window.location.href = "/login?message=Session%20expired";
        });
    }

    function keepAlive() {
        fetch("/api/auth/ping", { method: "GET" })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error("ping failed");
                }
                lastActivity = Date.now();
                hideWarning();
                resetTimers();
            })
            .catch(function () {
                forceLogout();
            });
    }

    function markActivity() {
        var now = Date.now();
        if (now - lastActivity < 1000) {
            return;
        }
        lastActivity = now;
        hideWarning();
        resetTimers();
    }

    ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach(function (eventName) {
        document.addEventListener(eventName, markActivity, { passive: true });
    });

    stayButton.addEventListener("click", keepAlive);
    logoutButton.addEventListener("click", forceLogout);

    resetTimers();
};
