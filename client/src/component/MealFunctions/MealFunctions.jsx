import React, { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { UserContext } from "../../context/UserContext";
import { useContext } from "react";
import DeleteCopyFunction from "./DeleteCopyFunction";
import ClipLoader from "react-spinners/ClipLoader";

export default function MealFunctions() {
    let loggedData = useContext(UserContext);
    const [date, setDate] = useState(new Date());
    const [displayMealNumber, setDisplayMealNumber] = useState(1);
    const [copyMealNumber, setCopyMealNumber] = useState(1);
    const [foodsByMeal, setFoodsByMeal] = useState({});
    const [selectedFoods, setSelectedFoods] = useState([]);
    const [copyDate, setCopyDate] = useState(formatDate(new Date())); // Format copyDate
    const [message, setMessage] = useState({ type: "", text: "" });
    const location = useLocation();
    const [loading, setLoading] = useState(true); // Initial loading state set to true
    const [color] = useState("#d73750"); // Color state for ClipLoader
    const [csrfToken, setCsrfToken] = useState('');

    // Function to format date as "YYYY-MM-DD"
    function formatDate(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    useEffect(() => {
        const queryParams = new URLSearchParams(location.search);
        const mealNumberParam = queryParams.get("mealNumber");
        const eatenDateParam = queryParams.get("eatenDate");
        const initialDate = eatenDateParam ? new Date(eatenDateParam) : new Date();
        const initialMealNumber = mealNumberParam ? parseInt(mealNumberParam) : 1;
        setDisplayMealNumber(initialMealNumber);
        setCopyMealNumber(initialMealNumber);
        setCopyDate(formatDate(initialDate)); // Update copyDate with formatted initialDate
    }, [location]);

    useEffect(() => {
        if (displayMealNumber) {
            fetchFoodItems(displayMealNumber);
        }
    }, [displayMealNumber]);

    useEffect(() => {
        async function fetchCsrfToken() {
            try {
                const response = await fetch("http://localhost:8000/csrf-token", { credentials: 'include' });
                const { csrfToken } = await response.json();
                console.log('CSRF Token fetched:', csrfToken);
                if (csrfToken) {
                    setCsrfToken(csrfToken);
                    document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; SameSite=Strict; path=/`;
                    console.log('CSRF Token stored in cookie:', csrfToken);
                }
            } catch (error) {
                console.error('Error fetching CSRF token:', error);
            }
        }

        fetchCsrfToken();
    }, []);

    const fetchFoodItems = (mealNumber) => {
        setLoading(true); // Set loading to true before fetching data
        const queryParams = new URLSearchParams(location.search);
        const eatenDateParam = queryParams.get("eatenDate");

        fetch(`http://localhost:8000/track/${loggedData.loggedUser.userid}/${mealNumber}/${eatenDateParam}`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                "csrf-token": csrfToken,
            },
            credentials: 'include'
        })
        .then((response) => {
            if (!response.ok) {
                throw new Error("Network response was not ok");
            }
            return response.json();
        })
        .then((data) => {
            setFoodsByMeal(prevState => ({
                ...prevState,
                [mealNumber]: data
            }));
            setLoading(false); // Set loading to false after data is fetched
        })
        .catch((error) => {
            console.error("Error fetching food items:", error);
            setLoading(false); // Set loading to false even if there is an error
        });
    };

    const refreshFoods = () => {
        fetchFoodItems(displayMealNumber);
    };

    const handleCopyMealNumberChange = (event) => {
        setCopyMealNumber(parseInt(event.target.value));
    };

    const handleCheckboxChange = (event, foodId) => {
        const isChecked = event.target.checked;
        const foodToAdd = foodsByMeal[displayMealNumber].find(food => food._id === foodId);

        setSelectedFoods(prevSelected => {
            const updatedSelected = isChecked
                ? [...prevSelected, foodToAdd]
                : prevSelected.filter(food => food._id !== foodId);
            console.log("Selected foods after change:", updatedSelected);
            return updatedSelected;
        });
    };

    console.log("Copy Date:", copyDate);

    function formatNumber(number) {
        if (number % 1 === 0) {
            return number.toString(); // No decimals if the number is an integer
        } else {
            return parseFloat(number.toFixed(1)).toString(); // Convert to float to remove trailing zeros and then to string
        }
    }

    return (
        <section className="container createfood-container">
            <h1>Yiyecekler</h1>
            <div className="meal-function-container">
                {loading ? (
                    <div className="spinner-container">
                        <ClipLoader
                            color={color}
                            loading={loading}
                            size={25}
                            aria-label="Loading Spinner"
                            data-testid="loader"
                        />
                    </div>
                ) : (
                    foodsByMeal[displayMealNumber] && foodsByMeal[displayMealNumber].map((food, index) => (
                        <ul key={index}>
                            <li>
                                <div className="check-box-container">
                                    <div className="check-box">
                                        <input 
                                            type="checkbox" 
                                            value={food._id} 
                                            onChange={(event) => handleCheckboxChange(event, food._id)}
                                        />
                                    </div>
                                    <div>
                                        <h4>{food.details.Name}</h4>
                                    </div>
                                </div>
                                <div className="food-info">
                                    <h4>{food.quantity}g -</h4>
                                    <p>{formatNumber(food.details.Calorie)} cal: {formatNumber(food.details.Protein)}p, {formatNumber(food.details.Carbohydrate)}k, {formatNumber(food.details.Fat)}y, {formatNumber(food.details.Fiber)}lif</p>
                                </div>
                            </li>
                        </ul>
                    ))
                )}
            </div>
            <div>
                <input
                    className="meal-function-date-box"
                    type="date"
                    value={copyDate} // Use copyDate directly
                    onChange={(event) => setCopyDate(formatDate(new Date(event.target.value)))} // Update copyDate
                />
                <select className="meal-selection" onChange={handleCopyMealNumberChange} value={copyMealNumber.toString()}>
                    {[1, 2, 3, 4, 5, 6].map((number) => (
                        <option key={number} value={number}>
                            {number}.Öğün
                        </option>
                    ))}
                </select>
            </div>
            {message.text && (
                <div className={`message ${message.type}`}>
                    {message.text}
                </div>
            )}
            <DeleteCopyFunction
                selectedFoods={selectedFoods}
                foodsByMeal={foodsByMeal} 
                setFoodsByMeal={setFoodsByMeal}
                mealNumber={copyMealNumber}
                copyDate={copyDate}
                refreshFoods={refreshFoods}
                setMessage={setMessage}  // Pass the setMessage function to DeleteCopyFunction
            />
        </section>
    );
}


