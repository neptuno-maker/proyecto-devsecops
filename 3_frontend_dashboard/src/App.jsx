import React, { useEffect, useState, useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend
} from 'recharts';
import { obtenerGuiaRemediacion } from './remediationKnowledge';
import './App.css';

const SEVERITY_COLORS = {
  Crítica: '#f85149',
  Alta: '#db6d28',
  Media: '#d29922',
  Baja: '#58a6ff'
};

function App() {
  const [resumen, setResumen] = useState({ Crítica: 0, Alta: 0, Media: 0, Baja: 0 });
  const [ejecuciones, setEjecuciones] = useState([]);
  const [vulnerabilidades, setVulnerabilidades] = useState([]);

  // Estados para filtros
  const [filtroSeveridad, setFiltroSeveridad] = useState('TODAS');
  const [filtroOrigen, setFiltroOrigen] = useState('TODOS');
  const [busquedaTexto, setBusquedaTexto] = useState('');
  const [filtroEstadoEjecucion, setFiltroEstadoEjecucion] = useState('TODOS');

  // Estado para el Modal de Remediación
  const [vulnerabilidadSeleccionada, setVulnerabilidadSeleccionada] = useState(null);

  useEffect(() => {
    fetch('http://localhost:5000/api/resumen')
      .then(res => res.json())
      .then(data => setResumen(data || { Crítica: 0, Alta: 0, Media: 0, Baja: 0 }))
      .catch(err => console.error("Error al cargar resumen:", err));

    fetch('http://localhost:5000/api/ejecuciones')
      .then(res => res.json())
      .then(data => setEjecuciones(Array.isArray(data) ? data : []))
      .catch(err => console.error("Error al cargar ejecuciones:", err));

    fetch('http://localhost:5000/api/vulnerabilidades')
      .then(res => res.json())
      .then(data => setVulnerabilidades(Array.isArray(data) ? data : []))
      .catch(err => console.error("Error al cargar vulnerabilidades:", err));
  }, []);

  const vulnerabilidadesFiltradas = useMemo(() => {
    return vulnerabilidades.filter(v => {
      const coincideSeveridad = filtroSeveridad === 'TODAS' || v.severidad === filtroSeveridad;
      const coincideOrigen = filtroOrigen === 'TODOS' || 
        v.herramienta_origen.toLowerCase().includes(filtroOrigen.toLowerCase());
      const coincideTexto = busquedaTexto === '' || 
        v.tipo_vulnerabilidad.toLowerCase().includes(busquedaTexto.toLowerCase()) ||
        v.archivo_afectado.toLowerCase().includes(busquedaTexto.toLowerCase());

      return coincideSeveridad && coincideOrigen && coincideTexto;
    });
  }, [vulnerabilidades, filtroSeveridad, filtroOrigen, busquedaTexto]);

  const ejecucionesFiltradas = useMemo(() => {
    return ejecuciones.filter(e => {
      return filtroEstadoEjecucion === 'TODOS' || e.estado_final === filtroEstadoEjecucion;
    });
  }, [ejecuciones, filtroEstadoEjecucion]);

  const exportarCSV = () => {
    if (vulnerabilidadesFiltradas.length === 0) {
      alert("No hay datos para exportar.");
      return;
    }
    const encabezados = ["ID", "Origen", "Tipo", "Severidad", "Recurso"];
    const filas = vulnerabilidadesFiltradas.map(v => [
      v.id_vulnerabilidad,
      `"${v.herramienta_origen}"`,
      `"${v.tipo_vulnerabilidad.replace(/"/g, '""')}"`,
      `"${v.severidad}"`,
      `"${v.archivo_afectado.replace(/"/g, '""')}"`
    ]);
    const contenidoCSV = [encabezados.join(','), ...filas.map(f => f.join(','))].join('\n');
    const blob = new Blob([contenidoCSV], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `reporte_devsecops_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
  };

  const pieData = Object.keys(resumen)
    .filter(key => resumen[key] > 0)
    .map(key => ({ name: key, value: resumen[key] }));

  const toolCount = vulnerabilidades.reduce((acc, curr) => {
    acc[curr.herramienta_origen] = (acc[curr.herramienta_origen] || 0) + 1;
    return acc;
  }, {});

  const barData = Object.keys(toolCount).map(tool => ({
    herramienta: tool,
    total: toolCount[tool]
  }));

  const guiaActual = vulnerabilidadSeleccionada ? obtenerGuiaRemediacion(vulnerabilidadSeleccionada) : null;

  return (
    <div className="dashboard-container">
      <header className="header">
        <div className="header-title-container">
          <h1>Centro de Control DevSecOps</h1>
          <p className="subtitle">Monitoreo Continuo del Pipeline de Seguridad y Quality Gate</p>
        </div>
        <div className="export-actions no-print">
          <button className="btn-export btn-csv" onClick={exportarCSV}>📥 Exportar CSV</button>
          <button className="btn-export btn-pdf" onClick={() => window.print()}>📄 Imprimir PDF</button>
        </div>
      </header>

      {/* Métricas */}
      <section className="metrics-grid">
        <div className="card metric-card criticas">
          <h3>Críticas</h3>
          <p className="metric-value">{resumen.Crítica || 0}</p>
        </div>
        <div className="card metric-card altas">
          <h3>Altas</h3>
          <p className="metric-value">{resumen.Alta || 0}</p>
        </div>
        <div className="card metric-card medias">
          <h3>Medias</h3>
          <p className="metric-value">{resumen.Media || 0}</p>
        </div>
        <div className="card metric-card bajas">
          <h3>Bajas</h3>
          <p className="metric-value">{resumen.Baja || 0}</p>
        </div>
      </section>

      {/* Gráficos */}
      <section className="charts-grid">
        <div className="card chart-card">
          <h2>Distribución por Severidad</h2>
          <div style={{ width: '100%', height: 260 }}>
            {pieData.length > 0 ? (
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={5}>
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || '#8884d8'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#fff' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : <p className="no-data">Sin datos</p>}
          </div>
        </div>

        <div className="card chart-card">
          <h2>Hallazgos por Herramienta</h2>
          <div style={{ width: '100%', height: 260 }}>
            {barData.length > 0 ? (
              <ResponsiveContainer>
                <BarChart data={barData} margin={{ top: 20, right: 20, left: -10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                  <XAxis dataKey="herramienta" stroke="#8b949e" />
                  <YAxis stroke="#8b949e" allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#fff' }} />
                  <Bar dataKey="total" fill="#58a6ff" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <p className="no-data">Sin datos</p>}
          </div>
        </div>
      </section>

      {/* Historial de Ejecución */}
      <section className="card section-card">
        <div className="section-header-flex">
          <h2>Historial de Ejecución del Pipeline</h2>
          <div className="filter-group no-print">
            <label>Estado:</label>
            <select value={filtroEstadoEjecucion} onChange={(e) => setFiltroEstadoEjecucion(e.target.value)} className="custom-select">
              <option value="TODOS">Todos</option>
              <option value="Bloqueado">Bloqueado</option>
              <option value="Aprobado">Aprobado</option>
              <option value="En Proceso">En Proceso</option>
            </select>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Fecha y Hora</th>
              <th>Commit Hash</th>
              <th>Decisión Quality Gate</th>
            </tr>
          </thead>
          <tbody>
            {ejecucionesFiltradas.map((e) => (
              <tr key={e.id_ejecucion}>
                <td>#{e.id_ejecucion}</td>
                <td>{e.fecha_inicio}</td>
                <td><code>{e.commit_hash}</code></td>
                <td>
                  <span className={`badge ${e.estado_final === 'Bloqueado' ? 'badge-danger' : e.estado_final === 'Aprobado' ? 'badge-success' : 'badge-warning'}`}>
                    {e.estado_final}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* Hallazgos con disparador de remediación */}
      <section className="card section-card">
        <div className="section-header-flex">
          <h2>Hallazgos de Seguridad (SAST / SCA / DAST)</h2>
          <span className="info-badge no-print">💡 Haz clic en cualquier fila para ver la guía de mitigación</span>
        </div>

        <div className="filters-toolbar no-print">
          <input
            type="text"
            placeholder="Buscar por archivo, función o tipo..."
            value={busquedaTexto}
            onChange={(e) => setBusquedaTexto(e.target.value)}
            className="search-input"
          />
          <div className="filter-group">
            <label>Severidad:</label>
            <select value={filtroSeveridad} onChange={(e) => setFiltroSeveridad(e.target.value)} className="custom-select">
              <option value="TODAS">Todas</option>
              <option value="Crítica">Crítica</option>
              <option value="Alta">Alta</option>
              <option value="Media">Media</option>
              <option value="Baja">Baja</option>
            </select>
          </div>
          <div className="filter-group">
            <label>Origen:</label>
            <select value={filtroOrigen} onChange={(e) => setFiltroOrigen(e.target.value)} className="custom-select">
              <option value="TODOS">Todos</option>
              <option value="SAST">SAST (Bandit)</option>
              <option value="SCA">SCA (pip-audit)</option>
              <option value="DAST">DAST</option>
            </select>
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>Origen</th>
              <th>Tipo de Vulnerabilidad</th>
              <th>Severidad</th>
              <th>Archivo / Recurso Afectado</th>
              <th className="no-print">Acción</th>
            </tr>
          </thead>
          <tbody>
            {vulnerabilidadesFiltradas.map((v) => (
              <tr 
                key={v.id_vulnerabilidad} 
                className="interactive-row"
                onClick={() => setVulnerabilidadSeleccionada(v)}
              >
                <td><strong>{v.herramienta_origen}</strong></td>
                <td>{v.tipo_vulnerabilidad}</td>
                <td><span className={`tag tag-${v.severidad.toLowerCase()}`}>{v.severidad}</span></td>
                <td><code>{v.archivo_afectado}</code></td>
                <td className="no-print">
                  <button className="btn-remediation">🛡️ Guía de Mitigación</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* Modal de Mitigación / Remediación */}
      {vulnerabilidadSeleccionada && (
        <div className="modal-overlay" onClick={() => setVulnerabilidadSeleccionada(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <span className={`tag tag-${vulnerabilidadSeleccionada.severidad.toLowerCase()}`}>
                  {vulnerabilidadSeleccionada.severidad}
                </span>
                <h3>{vulnerabilidadSeleccionada.tipo_vulnerabilidad}</h3>
              </div>
              <button className="btn-close" onClick={() => setVulnerabilidadSeleccionada(null)}>✖</button>
            </div>

            <div className="modal-body">
              <div className="remediation-meta">
                <p><strong>Clasificación:</strong> {guiaActual.cwe}</p>
                <p><strong>Recurso Afectado:</strong> <code>{vulnerabilidadSeleccionada.archivo_afectado}</code></p>
                <p><strong>Herramienta:</strong> {vulnerabilidadSeleccionada.herramienta_origen}</p>
              </div>

              <div className="remediation-section">
                <h4>📌 Diagnóstico Técnico</h4>
                <p>{guiaActual.descripcion}</p>
              </div>

              <div className="remediation-section">
                <h4>🛠️ Plan de Remediación</h4>
                <ul>
                  {guiaActual.pasos.map((paso, index) => (
                    <li key={index}>{paso}</li>
                  ))}
                </ul>
              </div>

              <div className="remediation-section">
                <h4>💻 Código / Configuración Sugerida</h4>
                <pre className="code-box"><code>{guiaActual.codigoSugerido}</code></pre>
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn-export btn-pdf" onClick={() => setVulnerabilidadSeleccionada(null)}>
                Cerrar Guía
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;