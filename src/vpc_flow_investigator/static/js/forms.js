// Form handling and validation
const Forms = {
  startPicker: null,
  endPicker: null,
  cidrStartPicker: null,
  cidrEndPicker: null,

  init() {
    this.initDatePickers();
    this.initEventListeners();
    this.initPortFieldToggle();
  },

  initDatePickers() {
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    this.startPicker = flatpickr("#start_time", {
      enableTime: true,
      dateFormat: "Y-m-d H:i",
      defaultDate: yesterday,
      maxDate: now,
    });

    this.endPicker = flatpickr("#end_time", {
      enableTime: true,
      dateFormat: "Y-m-d H:i",
      defaultDate: now,
      maxDate: now,
    });

    this.cidrStartPicker = flatpickr("#cidr_start_time", {
      enableTime: true,
      dateFormat: "Y-m-d H:i",
      defaultDate: yesterday,
      maxDate: now,
    });

    this.cidrEndPicker = flatpickr("#cidr_end_time", {
      enableTime: true,
      dateFormat: "Y-m-d H:i",
      defaultDate: now,
      maxDate: now,
    });
  },

  initEventListeners() {
    // Tab switching
    document.getElementById('analysisTab')?.addEventListener('click', () => this.switchTab('analysis'));
    document.getElementById('cidrTab')?.addEventListener('click', () => this.switchTab('cidr'));
    
    // Form submissions
    document.getElementById('analysisForm')?.addEventListener('submit', (e) => this.handleAnalysisSubmit(e));
    document.getElementById('cidrForm')?.addEventListener('submit', (e) => this.handleCidrSubmit(e));
    document.getElementById('recallBtn')?.addEventListener('click', () => this.handleRecall());
  },

  initPortFieldToggle() {
    document.getElementById("analysis")?.addEventListener("change", function () {
      const portField = document.getElementById("portField");
      const portInput = document.getElementById("port");
      if (this.value === "port-specific") {
        Utils.showElement("portField");
        portInput.required = true;
      } else {
        Utils.hideElement("portField");
        portInput.required = false;
        portInput.value = "";
      }
    });
  },

  switchTab(tab) {
    if (tab === 'analysis') {
      Utils.showElement('analysisPanel');
      Utils.hideElement('cidrPanel');
      this.setTabActive('analysisTab', 'cidrTab');
    } else {
      Utils.showElement('cidrPanel');
      Utils.hideElement('analysisPanel');
      this.setTabActive('cidrTab', 'analysisTab');
    }
  },

  setTabActive(activeId, inactiveId) {
    const active = document.getElementById(activeId);
    const inactive = document.getElementById(inactiveId);
    
    active.classList.add('border-b-2', 'border-blue-500', 'text-blue-600');
    active.classList.remove('text-gray-500');
    
    inactive.classList.remove('border-b-2', 'border-blue-500', 'text-blue-600');
    inactive.classList.add('text-gray-500');
  },

  async handleAnalysisSubmit(e) {
    e.preventDefault();
    
    if (!this.validateAnalysisForm()) return;
    
    const formData = this.prepareAnalysisData(e.target);
    await this.submitForm('/api/analyze', formData, 'analyzeBtn', 'btnText', 'btnSpinner');
  },

  async handleCidrSubmit(e) {
    e.preventDefault();
    
    if (!this.validateCidrForm()) return;
    
    const formData = this.prepareCidrData(e.target);
    await this.submitForm('/api/scan-cidrs', formData, 'cidrBtn', 'cidrBtnText', 'cidrBtnSpinner');
  },

  validateAnalysisForm() {
    const instanceId = document.getElementById("instance_id").value.trim();
    const region = document.getElementById("region").value.trim();
    const port = document.getElementById("port").value;
    const analysisType = document.getElementById("analysis").value;

    if (!Utils.validateInstanceId(instanceId)) {
      alert("Invalid Instance ID format. Must be like: i-0123456789abcdef0");
      return false;
    }

    if (!Utils.validateRegion(region)) {
      alert("Invalid region format. Must be like: us-east-1");
      return false;
    }

    if (analysisType === "port-specific") {
      const portNum = parseInt(port);
      if (!port || portNum < 1 || portNum > 65535) {
        alert("Port number must be between 1 and 65535");
        return false;
      }
    }

    return this.validateTimeRange(this.startPicker, this.endPicker);
  },

  validateCidrForm() {
    const logGroup = document.getElementById('log_group').value.trim();
    if (!logGroup) {
      alert('Please enter a log group name');
      return false;
    }
    
    return this.validateTimeRange(this.cidrStartPicker, this.cidrEndPicker);
  },

  validateTimeRange(startPicker, endPicker) {
    const startTime = startPicker.selectedDates[0];
    const endTime = endPicker.selectedDates[0];

    if (!startTime || !endTime) {
      alert("Please select both start and end times");
      return false;
    }

    if (startTime >= endTime) {
      alert("Start time must be before end time");
      return false;
    }

    const timeDiff = (endTime - startTime) / (1000 * 60 * 60 * 24);
    if (timeDiff > 7) {
      return confirm("Time range is more than 7 days. This may take a long time. Continue?");
    }

    return true;
  },

  prepareAnalysisData(form) {
    const formData = new FormData(form);
    const instanceId = document.getElementById("instance_id").value.trim();
    const region = document.getElementById("region").value.trim();
    
    formData.set("instance_id", Utils.sanitizeInput(instanceId));
    formData.set("region", Utils.sanitizeInput(region));
    formData.set("start_time", Math.floor(this.startPicker.selectedDates[0].getTime() / 1000).toString());
    formData.set("end_time", Math.floor(this.endPicker.selectedDates[0].getTime() / 1000).toString());
    
    return formData;
  },

  prepareCidrData(form) {
    const formData = new FormData(form);
    formData.set('start_time', Math.floor(this.cidrStartPicker.selectedDates[0].getTime() / 1000).toString());
    formData.set('end_time', Math.floor(this.cidrEndPicker.selectedDates[0].getTime() / 1000).toString());
    
    const fileInput = document.getElementById('cidr_upload');
    if (fileInput.files.length > 0) {
      formData.append('cidr_file', fileInput.files[0]);
    }
    
    return formData;
  },

  async submitForm(url, formData, btnId, textId, spinnerId) {
    const btn = document.getElementById(btnId);
    const btnText = document.getElementById(textId);
    const spinner = document.getElementById(spinnerId);
    const originalText = btnText.textContent;

    btn.disabled = true;
    btnText.textContent = url.includes('analyze') ? 'Analyzing...' : 'Scanning...';
    Utils.showElement(spinnerId);
    Utils.showElement('loadingState');
    Utils.hideElement('errorState');
    Utils.hideElement('results');

    try {
      const response = await fetch(url, { method: "POST", body: formData });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || error.message || "Request failed");
      }

      const data = await response.json();
      
      if (url.includes('analyze')) {
        Results.display(data, data.query_id);
      } else {
        alert('CIDR scan completed successfully!');
      }
    } catch (error) {
      console.error("Form submission error:", error);
      Utils.setElementText("errorMessage", error.message);
      Utils.showElement("errorState");
    } finally {
      btn.disabled = false;
      btnText.textContent = originalText;
      Utils.hideElement(spinnerId);
      Utils.hideElement('loadingState');
    }
  },

  async handleRecall() {
    const queryId = document.getElementById("recallQueryId").value.trim();
    if (!queryId) {
      alert("Please enter a Query ID");
      return;
    }

    if (!/^[a-zA-Z0-9-]+$/.test(queryId)) {
      alert("Invalid Query ID format");
      return;
    }

    try {
      const response = await fetch(`/api/query/${queryId}`);
      if (!response.ok) throw new Error("Query not found");

      const data = await response.json();
      Results.display(data, queryId);
    } catch (error) {
      alert(`Failed to recall query: ${error.message}`);
    }
  }
};