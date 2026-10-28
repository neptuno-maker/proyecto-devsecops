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
  Legend,
  LabelList
} from 'recharts';
import { obtenerGuiaRemediacion } from './remediationKnowledge';
import './App.css';
import Login from './Login';
import Register from './Register';

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

  // Estados para el filtro de fechas
  const [fechaInicio, setFechaInicio] = useState('');
  const [fechaFin, setFechaFin] = useState('');

  // Estado para el Modal de Remediación
  const [vulnerabilidadSeleccionada, setVulnerabilidadSeleccionada] = useState(null);
  const [usuarioAutenticado, setUsuarioAutenticado] = useState(
    sessionStorage.getItem('devsecops_user') || null
  );

  // Estado para alternar entre Login y Registro
  const [mostrarRegistro, setMostrarRegistro] = useState(false);

  // Estados para Paginación
  const [paginaEjecuciones, setPaginaEjecuciones] = useState(1);
  const ejecucionesPorPagina = 5;

  const [paginaHallazgos, setPaginaHallazgos] = useState(1);
  const hallazgosPorPagina = 10;

  const handleLogout = () => {
    sessionStorage.removeItem('devsecops_token');
    sessionStorage.removeItem('devsecops_user');
    setUsuarioAutenticado(null);
  };

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
      const cumpleEstado = filtroEstadoEjecucion === 'TODOS' || e.estado_final === filtroEstadoEjecucion;

      let cumpleFecha = true;
      if (fechaInicio || fechaFin) {
        const fechaEjecucion = new Date(e.fecha_inicio);
        const inicio = fechaInicio ? new Date(`${fechaInicio}T00:00:00`) : null;
        const fin = fechaFin ? new Date(`${fechaFin}T23:59:59`) : null;

        if (inicio && fechaEjecucion < inicio) cumpleFecha = false;
        if (fin && fechaEjecucion > fin) cumpleFecha = false;
      }

      return cumpleEstado && cumpleFecha;
    });
  }, [ejecuciones, filtroEstadoEjecucion, fechaInicio, fechaFin]);

  // Paginación para Ejecuciones
  const totalPaginasEjecuciones = Math.ceil(ejecucionesFiltradas.length / ejecucionesPorPagina) || 1;
  const ejecucionesPaginadas = useMemo(() => {
    const inicio = (paginaEjecuciones - 1) * ejecucionesPorPagina;
    return ejecucionesFiltradas.slice(inicio, inicio + ejecucionesPorPagina);
  }, [ejecucionesFiltradas, paginaEjecuciones, ejecucionesPorPagina]);

  // Paginación para Hallazgos
  const totalPaginasHallazgos = Math.ceil(vulnerabilidadesFiltradas.length / hallazgosPorPagina) || 1;
  const hallazgosPaginados = useMemo(() => {
    const inicio = (paginaHallazgos - 1) * hallazgosPorPagina;
    return vulnerabilidadesFiltradas.slice(inicio, inicio + hallazgosPorPagina);
  }, [vulnerabilidadesFiltradas, paginaHallazgos, hallazgosPorPagina]);

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

  // Orden estricto de seguridad: Crítica -> Alta -> Media -> Baja
  const severidadesOrdenadas = ['Crítica', 'Alta', 'Media', 'Baja'];
  const pieData = severidadesOrdenadas
    .filter(sev => (resumen[sev] || 0) > 0)
    .map(sev => ({ name: sev, value: resumen[sev] }));

  // Total de hallazgos
  const totalHallazgos = useMemo(() => {
    return (resumen.Crítica || 0) + (resumen.Alta || 0) + (resumen.Media || 0) + (resumen.Baja || 0);
  }, [resumen]);

  // Leyenda en orden estricto (Crítica, Alta, Media, Baja)
  const legendPayload = useMemo(() => {
    return severidadesOrdenadas
      .filter(sev => (resumen[sev] || 0) > 0)
      .map(sev => ({
        id: sev,
        value: sev,
        type: 'rect',
        color: SEVERITY_COLORS[sev]
      }));
  }, [resumen]);

  const toolCount = vulnerabilidades.reduce((acc, curr) => {
    acc[curr.herramienta_origen] = (acc[curr.herramienta_origen] || 0) + 1;
    return acc;
  }, {});

  const barData = Object.keys(toolCount).map(tool => ({
    herramienta: tool,
    total: toolCount[tool]
  }));

  const guiaActual = vulnerabilidadSeleccionada ? obtenerGuiaRemediacion(vulnerabilidadSeleccionada) : null;

  if (!usuarioAutenticado) {
    if (mostrarRegistro) {
      return <Register onSwitchToLogin={() => setMostrarRegistro(false)} />;
    }
    return (
      <Login 
        onLoginSuccess={(usr) => setUsuarioAutenticado(usr)} 
        onSwitchToRegister={() => setMostrarRegistro(true)}
      />
    );
  }

  return (
    <div className="dashboard-container">
      <header className="header">
        <div className="header-title-container">
          <h1>Centro de Control DevSecOps</h1>
          <p className="subtitle">Monitoreo Continuo del Pipeline de Seguridad y Quality Gate</p>
        </div>
        <div className="export-actions no-print">
          <button className="btn-export btn-csv" onClick={exportarCSV}>
            📥 Exportar CSV
          </button>
          <button className="btn-export btn-pdf" onClick={() => window.print()}>
            📄 Imprimir / Guardar PDF
          </button>
          <button
            onClick={handleLogout}
            style={{
              backgroundColor: 'rgba(248, 81, 73, 0.1)',
              border: '1px solid rgba(248, 81, 73, 0.35)',
              color: '#ff7b72',
              padding: '8px 14px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '13px',
              fontWeight: '500',
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(248, 81, 73, 0.25)';
              e.currentTarget.style.borderColor = '#f85149';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(248, 81, 73, 0.1)';
              e.currentTarget.style.borderColor = 'rgba(248, 81, 73, 0.35)';
            }}
          >
            Cerrar Sesión ({usuarioAutenticado})
          </button>
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
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="45%"
                    innerRadius={60}
                    outerRadius={88}
                    paddingAngle={4}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || '#8884d8'} />
                    ))}
                  </Pie>
                  <text
                    x="50%"
                    y="41%"
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill="#f0f6fc"
                    style={{ fontSize: '24px', fontWeight: 'bold' }}
                  >
                    {totalHallazgos}
                  </text>
                  <text
                    x="50%"
                    y="50%"
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill="#8b949e"
                    style={{ fontSize: '10px', fontWeight: '600', letterSpacing: '1px' }}
                  >
                    TOTAL
                  </text>
                  <Tooltip contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#fff' }} />
                  <Legend verticalAlign="bottom" height={36} payload={legendPayload} />
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
                <BarChart data={barData} margin={{ top: 25, right: 20, left: -10, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                  <XAxis dataKey="herramienta" stroke="#8b949e" />
                  <YAxis stroke="#8b949e" allowDecimals={false} domain={[0, dataMax => Math.ceil(dataMax * 1.2)]} />
                  <Tooltip contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#fff' }} />
                  <Bar dataKey="total" radius={[4, 4, 0, 0]}>
                    <LabelList dataKey="total" position="top" fill="#c9d1d9" fontSize={13} offset={8} />
                    {barData.map((entry, index) => {
                      let color = '#58a6ff';
                      if (entry.herramienta?.includes('SAST') || entry.herramienta?.includes('Bandit')) {
                        color = '#bc8cff';
                      } else if (entry.herramienta?.includes('DAST') || entry.herramienta?.includes('ZAP')) {
                        color = '#d29922';
                      }
                      return <Cell key={`cell-${index}`} fill={color} />;
                    })}
                  </Bar>
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
          <div className="filters-toolbar no-print" style={{ margin: 0, padding: 0, background: 'transparent' }}>
            <div className="filter-group">
              <label>Desde:</label>
              <input 
                type="date" 
                value={fechaInicio} 
                onChange={(e) => {
                  setFechaInicio(e.target.value);
                  setPaginaEjecuciones(1);
                }} 
                className="search-input" 
                style={{ width: '135px', padding: '6px' }}
              />
            </div>
            <div className="filter-group">
              <label>Hasta:</label>
              <input 
                type="date" 
                value={fechaFin} 
                onChange={(e) => {
                  setFechaFin(e.target.value);
                  setPaginaEjecuciones(1);
                }} 
                className="search-input" 
                style={{ width: '135px', padding: '6px' }}
              />
            </div>
            <div className="filter-group">
              <label>Estado:</label>
              <select 
                value={filtroEstadoEjecucion} 
                onChange={(e) => {
                  setFiltroEstadoEjecucion(e.target.value);
                  setPaginaEjecuciones(1);
                }} 
                className="custom-select"
              >
                <option value="TODOS">Todos</option>
                <option value="Bloqueado">Bloqueado</option>
                <option value="Aprobado">Aprobado</option>
                <option value="En Proceso">En Proceso</option>
              </select>
            </div>
          </div>
        </div>

        <div style={{ maxHeight: '330px', overflowY: 'auto' }}>
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
              {ejecucionesPaginadas.map((e) => (
                <tr key={e.id_ejecucion}>
                  <td>#{e.id_ejecucion}</td>
                  <td>{e.fecha_inicio}</td>
                  <td>
                    <code
                      title={e.commit_hash}
                      style={{
                        display: 'inline-block',
                        maxWidth: '130px',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        verticalAlign: 'middle'
                      }}
                    >
                      {e.commit_hash}
                    </code>
                  </td>
                  <td>
                    <span className={`badge ${e.estado_final === 'Bloqueado' ? 'badge-danger' : e.estado_final === 'Aprobado' ? 'badge-success' : 'badge-warning'}`}>
                      {e.estado_final}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Controles de Paginación Historial */}
        <div className="no-print" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px', padding: '4px 8px' }}>
          <button
            onClick={() => setPaginaEjecuciones(p => Math.max(p - 1, 1))}
            disabled={paginaEjecuciones === 1}
            style={{
              backgroundColor: paginaEjecuciones === 1 ? '#21262d' : '#238636',
              color: paginaEjecuciones === 1 ? '#484f58' : '#ffffff',
              border: '1px solid #30363d',
              padding: '6px 14px',
              borderRadius: '6px',
              cursor: paginaEjecuciones === 1 ? 'not-allowed' : 'pointer',
              fontSize: '12px'
            }}
          >
            ◀ Anterior
          </button>
          <span style={{ color: '#8b949e', fontSize: '13px' }}>
            Página <strong style={{ color: '#c9d1d9' }}>{paginaEjecuciones}</strong> de <strong style={{ color: '#c9d1d9' }}>{totalPaginasEjecuciones}</strong>
          </span>
          <button
            onClick={() => setPaginaEjecuciones(p => Math.min(p + 1, totalPaginasEjecuciones))}
            disabled={paginaEjecuciones >= totalPaginasEjecuciones}
            style={{
              backgroundColor: paginaEjecuciones >= totalPaginasEjecuciones ? '#21262d' : '#238636',
              color: paginaEjecuciones >= totalPaginasEjecuciones ? '#484f58' : '#ffffff',
              border: '1px solid #30363d',
              padding: '6px 14px',
              borderRadius: '6px',
              cursor: paginaEjecuciones >= totalPaginasEjecuciones ? 'not-allowed' : 'pointer',
              fontSize: '12px'
            }}
          >
            Siguiente ▶
          </button>
        </div>
      </section>

      {/* Hallazgos con disparador de remediación */}
      <section className="card section-card">
        <div className="section-header-flex">
          <h2>
            Hallazgos de Seguridad (SAST / SCA / DAST){' '}
            <span style={{ fontSize: '14px', color: '#8b949e', fontWeight: 'normal' }}>
              ({vulnerabilidadesFiltradas.length})
            </span>
          </h2>
          <span className="info-badge no-print">💡 Haz clic en cualquier fila para ver la guía de mitigación</span>
        </div>

        <div className="filters-toolbar no-print">
          <input
            type="text"
            placeholder="Buscar por archivo, función o tipo..."
            value={busquedaTexto}
            onChange={(e) => {
              setBusquedaTexto(e.target.value);
              setPaginaHallazgos(1);
            }}
            className="search-input"
          />
          <div className="filter-group">
            <label>Severidad:</label>
            <select 
              value={filtroSeveridad} 
              onChange={(e) => {
                setFiltroSeveridad(e.target.value);
                setPaginaHallazgos(1);
              }} 
              className="custom-select"
            >
              <option value="TODAS">Todas</option>
              <option value="Crítica">Crítica</option>
              <option value="Alta">Alta</option>
              <option value="Media">Media</option>
              <option value="Baja">Baja</option>
            </select>
          </div>
          <div className="filter-group">
            <label>Origen:</label>
            <select 
              value={filtroOrigen} 
              onChange={(e) => {
                setFiltroOrigen(e.target.value);
                setPaginaHallazgos(1);
              }} 
              className="custom-select"
            >
              <option value="TODOS">Todos</option>
              <option value="SAST">SAST (Bandit)</option>
              <option value="SCA">SCA (pip-audit)</option>
              <option value="DAST">DAST</option>
            </select>
          </div>
        </div>

        <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
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
              {hallazgosPaginados.map((v) => (
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
                    <button
                      className="btn-remediation"
                      style={{
                        backgroundColor: 'rgba(56, 139, 253, 0.1)',
                        border: '1px solid rgba(56, 139, 253, 0.4)',
                        color: '#58a6ff',
                        padding: '4px 10px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontSize: '12px',
                        fontWeight: '500'
                      }}
                    >
                      🛡️ Guía de Mitigación
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Controles de Paginación Hallazgos */}
        <div className="no-print" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px', padding: '4px 8px' }}>
          <button
            onClick={() => setPaginaHallazgos(p => Math.max(p - 1, 1))}
            disabled={paginaHallazgos === 1}
            style={{
              backgroundColor: paginaHallazgos === 1 ? '#21262d' : '#1f6feb',
              color: paginaHallazgos === 1 ? '#484f58' : '#ffffff',
              border: '1px solid #30363d',
              padding: '6px 14px',
              borderRadius: '6px',
              cursor: paginaHallazgos === 1 ? 'not-allowed' : 'pointer',
              fontSize: '12px'
            }}
          >
            ◀ Anterior
          </button>
          <span style={{ color: '#8b949e', fontSize: '13px' }}>
            Página <strong style={{ color: '#c9d1d9' }}>{paginaHallazgos}</strong> de <strong style={{ color: '#c9d1d9' }}>{totalPaginasHallazgos}</strong>
          </span>
          <button
            onClick={() => setPaginaHallazgos(p => Math.min(p + 1, totalPaginasHallazgos))}
            disabled={paginaHallazgos >= totalPaginasHallazgos}
            style={{
              backgroundColor: paginaHallazgos >= totalPaginasHallazgos ? '#21262d' : '#1f6feb',
              color: paginaHallazgos >= totalPaginasHallazgos ? '#484f58' : '#ffffff',
              border: '1px solid #30363d',
              padding: '6px 14px',
              borderRadius: '6px',
              cursor: paginaHallazgos >= totalPaginasHallazgos ? 'not-allowed' : 'pointer',
              fontSize: '12px'
            }}
          >
            Siguiente ▶
          </button>
        </div>
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