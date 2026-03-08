import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import './index.css'
import App from './App.jsx'
import Investigations from './pages/Investigations.jsx'
import WasmView from './pages/WasmView.jsx'
import PageTransition from './components/PageTransition.jsx'

function AnimatedRoutes() {
  const location = useLocation();
  
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<PageTransition><App /></PageTransition>} />
        <Route path="/investigations" element={<PageTransition><Investigations /></PageTransition>} />
        <Route path="/analysis/:id" element={<PageTransition><WasmView /></PageTransition>} />
      </Routes>
    </AnimatePresence>
  );
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <AnimatedRoutes />
    </BrowserRouter>
  </StrictMode>,
)
