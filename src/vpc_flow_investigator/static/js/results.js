// Results display and management
const Results = {
  display(data, queryId = null) {
    this.updateSummaryStats(data);
    this.updateQueryId(queryId);
    this.updateQuickStats(data);
    
    Charts.createTrafficChart(data.analyses.traffic_summary || []);
    
    Tables.populate("sshInboundTable", data.analyses.ssh_inbound || [], [
      "source_ip", "action", "organization", "count"
    ]);
    
    Tables.populate("externalInboundTable", data.analyses.external_inbound || [], [
      "source_ip", "action", "organization", "count"
    ]);

    this.displayAdditionalResults(data.analyses);
    Utils.showElement("results");
  },

  updateSummaryStats(data) {
    Utils.setElementText("totalLogs", Utils.formatNumber(data.total_logs));
    
    let accepted = 0, rejected = 0;
    Object.values(data.analyses).forEach((analysis) => {
      if (Array.isArray(analysis)) {
        analysis.forEach((item) => {
          if (item.action === "ACCEPT") accepted += item.count || 0;
          if (item.action === "REJECT") rejected += item.count || 0;
        });
      }
    });
    
    Utils.setElementText("acceptedTraffic", Utils.formatNumber(accepted));
    Utils.setElementText("rejectedTraffic", Utils.formatNumber(rejected));
  },

  updateQueryId(queryId) {
    if (queryId) {
      Utils.setElementText("queryId", queryId);
    }
  },

  updateQuickStats(data) {
    Utils.setElementText("quickTotalLogs", Utils.formatNumber(data.total_logs));
    
    let accepted = 0, rejected = 0;
    Object.values(data.analyses).forEach((analysis) => {
      if (Array.isArray(analysis)) {
        analysis.forEach((item) => {
          if (item.action === "ACCEPT") accepted += item.count || 0;
          if (item.action === "REJECT") rejected += item.count || 0;
        });
      }
    });
    
    Utils.setElementText("quickAccepted", Utils.formatNumber(accepted));
    Utils.setElementText("quickRejected", Utils.formatNumber(rejected));
  },

  displayAdditionalResults(analyses) {
    const container = document.getElementById("additionalResults");
    if (!container) return;
    
    container.innerHTML = "";

    const resultTypes = [
      { key: 'ssh_response', title: 'SSH Response Traffic', columns: ['destination_ip', 'action', 'organization', 'count'] },
      { key: 'ssh_outbound', title: 'SSH Outbound Connections', columns: ['destination_ip', 'action', 'organization', 'count'] },
      { key: 'external_summary', title: 'External Traffic Summary', columns: ['action', 'count'] },
      { key: 'port_specific', title: 'Port-Specific Traffic', columns: ['source_ip', 'destination_ip', 'action', 'count'] },
      { key: 'sensitive_ports', title: 'Sensitive Ports Traffic', columns: ['source_ip', 'port', 'action', 'organization', 'count'] }
    ];

    resultTypes.forEach(({ key, title, columns }) => {
      if (analyses[key]) {
        this.createAnalysisSection(container, title, analyses[key], columns);
      }
    });

    if (analyses.top_external) {
      this.createExternalFlowsSection(container, analyses.top_external);
    }

    if (analyses.rejected) {
      this.createRejectedTrafficSection(container, analyses.rejected);
    }
  },

  createAnalysisSection(container, title, data, columns) {
    const section = document.createElement("div");
    section.className = "bg-white rounded-lg shadow-md p-6 mb-8";

    const heading = document.createElement("h3");
    heading.className = "text-xl font-semibold mb-4";
    heading.textContent = title;
    section.appendChild(heading);

    const table = Tables.createFlowTable(data, columns);
    section.appendChild(table);
    container.appendChild(section);
  },

  createExternalFlowsSection(container, data) {
    const section = document.createElement("div");
    section.className = "bg-white rounded-lg shadow-md p-6 mb-8 lcars-card";

    const heading = document.createElement("h3");
    heading.className = "text-xl font-semibold mb-4";
    heading.innerHTML = `
      <span data-theme-target="default">External Traffic Flows</span>
      <span data-theme-target="lcars" class="hidden text-orange-400 uppercase">External Network Analysis</span>
    `;
    section.appendChild(heading);

    const mainGrid = document.createElement("div");
    mainGrid.className = "grid grid-cols-1 xl:grid-cols-2 gap-6";

    const inboundData = this.separateFlowData(data, false);
    const outboundData = this.separateFlowData(data, true);

    mainGrid.appendChild(this.createFlowSection("Inbound (External → Server)", "Incoming Connections", inboundData, ["source_ip", "port", "count", "src_org"]));
    mainGrid.appendChild(this.createFlowSection("Outbound (Server → External)", "Outgoing Connections", outboundData, ["destination_ip", "port", "count", "dst_org"]));

    section.appendChild(mainGrid);
    container.appendChild(section);
  },

  createRejectedTrafficSection(container, data) {
    const section = document.createElement("div");
    section.className = "bg-white rounded-lg shadow-md p-6 mb-8 lcars-card";

    const heading = document.createElement("h3");
    heading.className = "text-xl font-semibold mb-4";
    heading.innerHTML = `
      <span data-theme-target="default">Rejected Traffic</span>
      <span data-theme-target="lcars" class="hidden text-red-400 uppercase">Security Blocks</span>
    `;
    section.appendChild(heading);

    const gridContainer = document.createElement("div");
    gridContainer.className = "grid grid-cols-1 lg:grid-cols-2 gap-6";

    const inboundRejected = data.filter(flow => !flow.source_ip.startsWith("10.120."));
    const outboundRejected = data.filter(flow => flow.source_ip.startsWith("10.120."));

    gridContainer.appendChild(this.createRejectedSection("Inbound Rejected", inboundRejected, ["source_ip", "port", "count", "external_org"]));
    gridContainer.appendChild(this.createRejectedSection("Outbound Rejected", outboundRejected, ["destination_ip", "port", "count", "external_org"]));

    section.appendChild(gridContainer);
    container.appendChild(section);
  },

  separateFlowData(data, isOutbound) {
    const accepted = data.filter(flow => 
      (isOutbound ? flow.source_ip.startsWith("10.120.") : !flow.source_ip.startsWith("10.120.")) && 
      flow.action === "ACCEPT"
    );
    const rejected = data.filter(flow => 
      (isOutbound ? flow.source_ip.startsWith("10.120.") : !flow.source_ip.startsWith("10.120.")) && 
      flow.action === "REJECT"
    );
    return { accepted, rejected };
  },

  createFlowSection(title, lcarsTitle, data, columns) {
    const section = document.createElement("div");
    section.innerHTML = `
      <h4 class="text-lg font-medium mb-3 text-blue-600">
        <span data-theme-target="default">${title}</span>
        <span data-theme-target="lcars" class="hidden text-cyan-400 uppercase">${lcarsTitle}</span>
      </h4>
    `;

    const grid = document.createElement("div");
    grid.className = "grid grid-cols-1 lg:grid-cols-2 gap-4";

    grid.appendChild(this.createSubSection("Accepted", "text-green-600", data.accepted, columns));
    grid.appendChild(this.createSubSection("Rejected", "text-red-600", data.rejected, columns));

    section.appendChild(grid);
    return section;
  },

  createSubSection(title, colorClass, data, columns) {
    const div = document.createElement("div");
    div.innerHTML = `<h5 class="text-md font-medium mb-2 ${colorClass}">${title}</h5>`;
    div.appendChild(Tables.createFlowTable(data, columns));
    return div;
  },

  createRejectedSection(title, data, columns) {
    const div = document.createElement("div");
    div.innerHTML = `<h4 class="text-lg font-medium mb-3 text-red-600">${title}</h4>`;
    div.appendChild(Tables.createFlowTable(data, columns));
    return div;
  }
};