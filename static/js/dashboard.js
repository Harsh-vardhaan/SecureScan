"use strict";

document.addEventListener("DOMContentLoaded", function () {
    const scanForm = document.getElementById("scanForm");
    const targetInput = document.getElementById("targetInput");
    const authorizationCheckbox = document.getElementById("authConfirmed");
    const startButton = document.getElementById("startScanBtn");
    const buttonIcon = document.getElementById("btnIcon");
    const buttonText = document.getElementById("btnText");
    const scanStatus = document.getElementById("scanStatus");
    const newScanControl = document.getElementById("newScanControl");
    const resultSection = document.getElementById("scanResultsSection");
    const activeMetricsHeading = document.getElementById("activeScanMetricsHeading");
    const activeMetrics = document.getElementById("activeScanMetrics");

    if (scanForm && startButton) {
        scanForm.addEventListener("submit", function () {
            startButton.disabled = true;
            buttonIcon.className = "spinner-border spinner-border-sm";
            buttonText.textContent = "Scanning...";

            if (scanStatus) {
                scanStatus.textContent =
                    "Authorized assessment started. Please wait for results.";
            }
        });
    }

    if (!newScanControl || !scanForm || !targetInput) {
        return;
    }

    newScanControl.addEventListener("click", function (event) {
        event.preventDefault();

        if (resultSection) {
            resultSection.hidden = true;
        }
        if (activeMetricsHeading) {
            activeMetricsHeading.hidden = true;
        }
        if (activeMetrics) {
            activeMetrics.hidden = true;
        }

        targetInput.value = "";
        if (authorizationCheckbox) {
            authorizationCheckbox.checked = false;
        }
        if (startButton) {
            startButton.disabled = false;
        }
        if (buttonIcon) {
            buttonIcon.className = "bi bi-play-fill fs-5";
        }
        if (buttonText) {
            buttonText.textContent = "Start Scan";
        }
        if (scanStatus) {
            scanStatus.textContent =
                "Ready for a new authorized assessment. Previous results remain saved in scan history.";
        }

        const reduceMotion = window.matchMedia(
            "(prefers-reduced-motion: reduce)"
        ).matches;
        scanForm.scrollIntoView({
            behavior: reduceMotion ? "auto" : "smooth",
            block: "center",
        });
        targetInput.focus({ preventScroll: true });
    });
});
