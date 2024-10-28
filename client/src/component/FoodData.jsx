import { useState, useEffect, useContext } from "react";
import { UserContext } from "../context/UserContext";
import { useNavigate, useLocation } from "react-router-dom";
import Footer from "./Footer";

export default function FoodData(props) {
    // ------------------Variables------------------ 
    const location = useLocation();
    const { foodItem, details, quantity, id, mealNumber: initialMealNumber, eatenDate } = location.state || {};

    const [food, setFood] = useState(details || null);
    const [foodInitial, setFoodInitial] = useState({});
    const [eatenQuantity, setEatenQuantity] = useState(quantity || 100);
    const [initialEatenQuantity, setInitialEatenQuantity] = useState(quantity || 100); // New state for initial quantity
    const [mealNumber, setMealNumber] = useState(initialMealNumber || 1);
    const [csrfToken, setCsrfToken] = useState('');

    console.log('Initial EatenQuantity:', initialEatenQuantity);

    const handleMealNumberChange = (event) => {
        setMealNumber(parseInt(event.target.value)); // Convert value to integer
    };

    let loggedData = useContext(UserContext);

    const [message, setMessage] = useState({
        type: "",
        text: ""
    });

    const navigate = useNavigate();

    useEffect(() => {
        const initialFood = details || foodItem || {};
        setFood({ ...initialFood, _id: initialFood._id });
        setFoodInitial({
            Protein: initialFood.Protein || 0,
            Carbohydrate: initialFood.Carbohydrate || 0,
            Fat: initialFood.Fat || 0,
            Fiber: initialFood.Fiber || 0,
            Calorie: initialFood.Calorie || 0
        });

        console.log('Initial food set:', initialFood);

        // Set the initial eaten quantity
        setInitialEatenQuantity(quantity || 100);
    }, [foodItem, details, quantity]);

    useEffect(() => {
        if (details) {
            setFood(prevState => ({ ...prevState, NameTr: details.Name, _id: details.foodId }));
        }
    }, [details]);

    useEffect(() => {
        if (details) {
            const quantity = initialEatenQuantity; // Use initialEatenQuantity instead of eatenQuantity
            console.log('Eaten Quantity:', quantity);
            const calculatedFood = {
                ...details,
                NameTr: details.Name || "Ferrero Rocher",
                _id: details.foodId,
                Calorie: (details.Calorie * 100) / quantity,
                Protein: (details.Protein * 100) / quantity,
                Carbohydrate: (details.Carbohydrate * 100) / quantity,
                Fat: (details.Fat * 100) / quantity,
                Fiber: (details.Fiber * 100) / quantity,
            };

            console.log('Details:', details);
            console.log('Eaten Quantity:', quantity);
            console.log('Calculated Food:', calculatedFood);

            setFoodInitial(calculatedFood);
            console.log('Food Initial set:', calculatedFood);
        }
    }, [details, initialEatenQuantity]); // Update dependency to initialEatenQuantity

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

    function calculateMacros(event) {
        if (event.target.value.length !== 0) {
            let quantity = Number(event.target.value);
            setEatenQuantity(quantity); // This changes the current eaten quantity, but calculations will use initialEatenQuantity

            let copyFood = { ...food };

            if (foodInitial.Protein !== undefined && foodInitial.Carbohydrate !== undefined &&
                foodInitial.Fat !== undefined && foodInitial.Fiber !== undefined && foodInitial.Calorie !== undefined) {
                copyFood.Protein = (foodInitial.Protein * quantity) / 100;
                copyFood.Carbohydrate = (foodInitial.Carbohydrate * quantity) / 100;
                copyFood.Fat = (foodInitial.Fat * quantity) / 100;
                copyFood.Fiber = (foodInitial.Fiber * quantity) / 100;
                copyFood.Calorie = (foodInitial.Calorie * quantity) / 100;
                console.log('Calculated macros:', copyFood);
            } else {
                console.error('Food initial values are not properly defined', foodInitial);
            }

            setFood(copyFood);
        }
    }

    function createFoodItem(trackedItem) {
        fetch("http://localhost:8000/track", {
            method: "POST",
            body: JSON.stringify(trackedItem),
            headers: {
                "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                "Content-type": "application/json",
                "csrf-token": csrfToken
            },
            credentials: 'include'
        })
        .then((response) => {
            return response.json().then(data => {
                if (response.status === 201) {
                    setMessage({ type: "success", text: "Başarıyla eklendi!" });
                    navigate("/diet");
                } else {
                    setMessage({ type: "error", text: "Bir hata oluştu!" });
                }
                setTimeout(() => {
                    setMessage({ type: "", text: "" });
                }, 1000);
                console.log(data);
            });
        })
        .catch((err) => {
            console.log(err);
        });
    }

    function updateFoodItem(trackedItem) {
        fetch(`http://localhost:8000/track/${trackedItem.id}`, {
            method: "PUT",
            body: JSON.stringify(trackedItem),
            headers: {
                "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                "Content-type": "application/json",
                "csrf-token": csrfToken,
            },
            credentials: 'include'
        })
        .then((response) => {
            return response.json().then(data => {
                if (response.status === 200) {
                    setMessage({ type: "success", text: "Başarıyla güncellendi!" });
                    navigate("/diet");
                } else if (response.status === 404) {
                    setMessage({ type: "error", text: "Tracking document not found!" });
                } else {
                    setMessage({ type: "error", text: "Bir hata oluştu!" });
                }
                setTimeout(() => {
                    setMessage({ type: "", text: "" });
                }, 1000);
                console.log(data);
            });
        })
        .catch((err) => {
            console.error(err);
            setMessage({ type: "error", text: "Network or server error!" });
        });
    }

    function trackFoodItem() {
        let trackedItem = {
            userId: loggedData.loggedUser.userid,
            foodId: food._id,
            details: {
                Name: food.NameTr,
                Protein: food.Protein,
                Carbohydrate: food.Carbohydrate,
                Fat: food.Fat,
                Fiber: food.Fiber,
                Calorie: food.Calorie
            },
            quantity: eatenQuantity,
            mealNumber: mealNumber,
            eatenDate: eatenDate,
            id: id
        };

        if (id) {
            updateFoodItem(trackedItem);
        } else {
            createFoodItem(trackedItem);
        }
    }
    console.log('foodData eatendate:', eatenDate);

    function formatNumber(number) {
        if (number % 1 === 0) {
            return number.toString(); // No decimals if the number is an integer
        } else {
            return parseFloat(number.toFixed(1)).toString(); // Convert to float to remove trailing zeros and then to string
        }
    }

    return (
        <section className="container fooddata-container">
        <Footer />
        <div className="food">
            {food && ( // Add conditional check here
                <>
                    <h3>
                        {food.NameTr} - <span className="eatenQuantity">{eatenQuantity}g:</span> <span className="calorie">{formatNumber(food.Calorie)}kcal</span>
                    </h3>

                    <div className="macros">
                        <div className="nutrient">
                            <div className="macro-details">
                                <p className="n-title">Protein</p>
                                <p className="n-value">{formatNumber(food.Protein)}g</p>
                            </div>
                            <div className="macro-details">
                                <p className="n-title">Karb</p>
                                <p className="n-value">{formatNumber(food.Carbohydrate)}g</p>
                            </div>
                            <div className="macro-details">
                                <p className="n-title">Yağ</p>
                                <p className="n-value">{formatNumber(food.Fat)}g</p>
                            </div>
                            <div className="macro-details">
                                <p className="n-title">Lif</p>
                                <p className="n-value">{formatNumber(food.Fiber)}g</p>
                            </div>
                        </div>
                    </div>
                    <div className="food-quantity-button">
                        <div className="meal-label-selection">
                            <label className="meal-label">Öğün seçin: </label>
                            <select className="meal-selection" value={mealNumber} onChange={handleMealNumberChange}>
                                <option value={1}>1.Öğün</option>
                                <option value={2}>2.Öğün</option>
                                <option value={3}>3.Öğün</option>
                                <option value={4}>4.Öğün</option>
                                <option value={5}>5.Öğün</option>
                                <option value={6}>6.Öğün</option>
                            </select>  
                        </div>
                        <div className="food-quantity">
                            <span>Miktar:</span>   
                            <input
                                type="number"
                                onChange={calculateMacros}
                                className="inp-quant"
                                placeholder="Giriş yapın"
                            />
                        </div>
                        <div className="save-btn">
                            <button className="btn-add" onClick={trackFoodItem}>Kaydet</button>
                        </div>
                    </div>
                    <p className={message.type}>{message.text}</p>
                </>
            )}
        </div>
    </section> 
    );
}