import './App.css'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Register from './component/Register'
import Login from './component/Login'
import NotFound from './component/NotFound'
import Diet from './component/Diet'
import Private from './component/Private'
import SearchFood from './component/SearchFood'
import FoodData from './component/FoodData'
import Demo from './component/Demo'
import CreateFood from './component/CreateFood'
import TrackWeight from './component/TrackWeight'
import MealFunctions from './component/MealFunctions/MealFunctions'
import ForgotPassword from './component/ForgotPassword'
import ResetPassword from './component/ResetPassword'
import VerifyEmail from './component/VerifyEmail'
import More from './component/More/More'
import Account from './component/More/General/Account'
import Profile from './component/More/General/Profile'
import About from './component/More/HelpInfo/About'

import { UserContext } from './context/UserContext'
import { useEffect, useState } from 'react'
import { useAuth } from './component/UseAuth'; // Correctly import the hook

function App() {
    // Use useAuth hook to manage the auth logic
    const { loggedUser, setLoggedUser, csrfToken } = useAuth();  
    const [currentDateView, setCurrentDateView] = useState(new Date());

    useEffect(() => {
        if (loggedUser) {
            console.log("Logged User updated:", loggedUser);
        }
    }, [loggedUser]);

    return (
        <UserContext.Provider value={{ loggedUser, setLoggedUser, currentDateView, setCurrentDateView }}>
            <BrowserRouter>
                <Routes>
                    {/* Register & Login */}
                    <Route path='/' element={<Diet />} />
                    <Route path='/login' element={<Login />} />
                    <Route path='/forgotpassword' element={<ForgotPassword />} />
                    <Route path='/resetpassword/:id/:token' element={<ResetPassword />} />
                    <Route path='/register' element={<Register />} />
                    <Route path='/verify/:id/:token' element={<VerifyEmail />} />

                    {/* Diet & Weight Tracking */}
                    <Route path='/diet' element={<Private Component={Diet} />} />
                    <Route path='/search' element={<Private Component={SearchFood} />} />
                    <Route path='/fooddata' element={<Private Component={FoodData} />} />
                    <Route path='/createfood' element={<Private Component={CreateFood} />} />
                    <Route path='/weight' element={<Private Component={TrackWeight} />} />
                    
                    <Route path='/mealfunctions' element={<Private Component={MealFunctions} />} />
                    
                    {/* More */}
                    <Route path='/more' element={<Private Component={More} />} />

                    {/* General */}
                    <Route path='/account' element={<Private Component={Account} />} />
                    <Route path='/profile' element={<Private Component={Profile} />} />

                    {/* Help & Info */}
                    <Route path='/about' element={<Private Component={About} />} />
                    
                    {/* Error */}
                    <Route path='/*' element={<NotFound />} />

                    {/* Template */}
                    <Route path='/demo' element={<Private Component={Demo} />} />
                </Routes>
            </BrowserRouter>
        </UserContext.Provider>
    );
}

export default App;