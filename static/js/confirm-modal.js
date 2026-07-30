"use strict";

document.addEventListener("DOMContentLoaded", function () {
    const modal = document.getElementById("confirmModal");
    const title = document.getElementById("confirmModalTitle");
    const description = document.getElementById("confirmModalDescription");
    const supportingText = document.getElementById("confirmModalSupportingText");
    const cancelButton = document.getElementById("confirmModalCancel");
    const submitButton = document.getElementById("confirmModalSubmit");
    const backgroundRegions = document.querySelectorAll("[data-modal-background]");
    let activeForm = null;
    let openingControl = null;

    if (!modal || !cancelButton || !submitButton) {
        return;
    }

    function setBackgroundDisabled(disabled) {
        backgroundRegions.forEach(function (region) {
            region.inert = disabled;
        });
        document.body.classList.toggle("secure-modal-open", disabled);
    }

    function closeModal() {
        modal.hidden = true;
        setBackgroundDisabled(false);
        activeForm = null;
        if (openingControl) {
            openingControl.focus();
            openingControl = null;
        }
    }

    function openModal(control) {
        const form = document.getElementById(control.dataset.confirmForm);
        if (!form) {
            return;
        }

        activeForm = form;
        openingControl = control;
        title.textContent = control.dataset.confirmTitle;
        description.textContent = control.dataset.confirmMessage;
        supportingText.textContent = control.dataset.confirmSupporting;
        submitButton.textContent = control.dataset.confirmAction;
        modal.hidden = false;
        setBackgroundDisabled(true);
        cancelButton.focus();
    }

    document.querySelectorAll("[data-confirm-modal]").forEach(function (control) {
        control.addEventListener("click", function () {
            openModal(control);
        });
    });

    cancelButton.addEventListener("click", closeModal);
    submitButton.addEventListener("click", function () {
        if (!activeForm) {
            return;
        }
        const field = activeForm.querySelector("[data-confirm-field]");
        if (field) {
            field.disabled = false;
        }
        activeForm.requestSubmit();
    });

    modal.addEventListener("click", function (event) {
        if (event.target === modal) {
            closeModal();
        }
    });

    modal.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
            event.preventDefault();
            closeModal();
            return;
        }
        if (event.key !== "Tab") {
            return;
        }

        const focusable = [cancelButton, submitButton];
        const currentIndex = focusable.indexOf(document.activeElement);
        const nextIndex = event.shiftKey
            ? (currentIndex - 1 + focusable.length) % focusable.length
            : (currentIndex + 1) % focusable.length;
        event.preventDefault();
        focusable[nextIndex].focus();
    });
});
