// Table creation and population
const Tables = {
  populate(tableId, data, columns) {
    const tbody = document.getElementById(tableId);
    if (!tbody) return;
    
    tbody.innerHTML = "";

    data.forEach((row) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-gray-50";

      columns.forEach((col) => {
        const td = document.createElement("td");
        td.className = "px-4 py-2 text-sm text-gray-900";
        td.textContent = row[col] || "-";
        tr.appendChild(td);
      });

      tbody.appendChild(tr);
    });

    if (data.length === 0) {
      this.addEmptyRow(tbody, columns.length, "No data available");
    }
  },

  addEmptyRow(tbody, colSpan, message) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = colSpan;
    td.className = "px-4 py-2 text-sm text-gray-500 text-center";
    td.textContent = message;
    tr.appendChild(td);
    tbody.appendChild(tr);
  },

  createFlowTable(data, columns) {
    const tableContainer = document.createElement("div");
    tableContainer.className = "overflow-x-auto";

    const table = document.createElement("table");
    table.className = "min-w-full table-auto lcars-table text-sm";

    const thead = this.createTableHeader(columns);
    const tbody = this.createTableBody(data, columns);

    table.appendChild(thead);
    table.appendChild(tbody);
    tableContainer.appendChild(table);
    
    return tableContainer;
  },

  createTableHeader(columns) {
    const thead = document.createElement("thead");
    thead.className = "bg-gray-50";
    const headerRow = document.createElement("tr");

    const columnLabels = {
      source_ip: "Source IP",
      destination_ip: "Dest IP",
      port: "Port",
      action: "Action",
      count: "Count",
      src_org: "Organization",
      dst_org: "Organization",
      external_org: "Organization",
      organization: "Organization",
    };

    columns.forEach((col) => {
      const th = document.createElement("th");
      th.className = "px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase";
      th.textContent = columnLabels[col] || col;
      headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    return thead;
  },

  createTableBody(data, columns) {
    const tbody = document.createElement("tbody");
    tbody.className = "bg-white divide-y divide-gray-200";

    data.forEach((row) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-gray-50";

      columns.forEach((col) => {
        const td = document.createElement("td");
        td.className = "px-3 py-2 text-sm text-gray-900";
        td.textContent = row[col] || "-";
        tr.appendChild(td);
      });

      tbody.appendChild(tr);
    });

    if (data.length === 0) {
      this.addEmptyRow(tbody, columns.length, "No data available");
    }

    return tbody;
  }
};