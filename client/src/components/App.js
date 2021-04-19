import './App.css';
import { BrowserRouter, Route, Switch } from 'react-router-dom'

import Home from '../pages/Home'
import Login from '../pages/Login'
import Register from '../pages/Register'
import Dashboard from '../pages/Dashboard'
import Navigation from './navigation/Navigation'

function App() {
  return (
    <BrowserRouter>
      <div className="container">
        <Navigation />
        <Switch>
          <Route path='/' exact component={Home} />
          <Route path='/login' component={Login} />
          <Route path='/Register' component={Register} />
          <Route path='/Dashboard' component={Dashboard} />
        </Switch>
      </div>
    </BrowserRouter>
  );
}

export default App;
