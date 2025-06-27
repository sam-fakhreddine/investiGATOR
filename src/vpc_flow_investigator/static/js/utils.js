// Utility functions for validation and sanitization
const Utils = {
  validateInstanceId(instanceId) {
    const pattern = /^i-[0-9a-f]{8,17}$/;
    return pattern.test(instanceId);
  },

  validateRegion(region) {
    if (!region) return false;
    const pattern = /^[a-z]{2}-[a-z]+-[0-9]$/;
    return pattern.test(region);
  },

  sanitizeInput(input) {
    return input.replace(/[<>"'&]/g, "");
  },

  showElement(elementId) {
    document.getElementById(elementId).classList.remove("hidden");
  },

  hideElement(elementId) {
    document.getElementById(elementId).classList.add("hidden");
  },

  setElementText(elementId, text) {
    const element = document.getElementById(elementId);
    if (element) element.textContent = text;
  },

  formatNumber(num) {
    return num.toLocaleString();
  }
};