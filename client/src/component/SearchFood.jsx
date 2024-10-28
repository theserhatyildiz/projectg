import { useContext, useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import Header from './Header';
import Footer from "./Footer";
import { UserContext } from "../context/UserContext";
import ClipLoader from "react-spinners/ClipLoader";
import debounce from 'lodash.debounce'; // Import debounce utility

export default function SearchFood() {
    const loggedData = useContext(UserContext);
    const { loggedUser } = loggedData; // Destructure loggedUser from loggedData
    console.log("SearchFood loggedUser:", loggedUser);
    console.log("SearchFood loggedData:", loggedData);
    const location = useLocation();
    const navigate = useNavigate(); // Initialize useNavigate
    const { foodItem, details, quantity, id, mealNumber, eatenDate } = location.state || {};

    const [foodItems, setFoodItems] = useState([]);
    const [food, setFood] = useState(foodItem || null);
    const [loading, setLoading] = useState(false);
    const [color] = useState("#d73750");
    const [csrfToken, setCsrfToken] = useState('');

    console.log("Search Page eatenDate:", eatenDate)

    useEffect(() => {
        if (foodItem) {
            setFood(foodItem);
        }
    }, [foodItem]);

    console.log("SearchFood food items:", { foodItems });

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

    // Debounced search function with a delay of 500ms
    const debouncedSearchFood = debounce(async (query) => {
        if (query.length !== 0) {
            setLoading(true);
            try {
                if (!csrfToken) {
                    console.error('CSRF token is not available');
                    setLoading(false);
                    return;
                }

                const [foodsResponse, userFoodsResponse] = await Promise.all([
                    fetch(`http://localhost:8000/foods/${query}`, {
                        method: "GET",
                        headers: {
                            "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                            "CSRF-Token": csrfToken // Include CSRF token in headers
                        },
                        credentials: 'include'
                    }),
                    fetch(`http://localhost:8000/userfoods/${query}`, {
                        method: "GET",
                        headers: {
                            "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                            "CSRF-Token": csrfToken // Include CSRF token in headers
                        },
                        credentials: 'include'
                    })
                ]);

                const foodsData = await foodsResponse.json();
                const userFoodsData = await userFoodsResponse.json();

                const combinedData = [
                    ...(foodsData.message === undefined ? foodsData : []),
                    ...(userFoodsData.message === undefined ? userFoodsData : [])
                ];

                setFoodItems(combinedData);
            } catch (err) {
                console.log(err);
                setFoodItems([]);
            } finally {
                setLoading(false);
            }
        } else {
            setFoodItems([]);
            setLoading(false);
        }
    }, 500);

    useEffect(() => {
        // Cleanup debounce function on component unmount
        return () => {
            debouncedSearchFood.cancel();
        };
    }, []);

    // Handle input change and trigger debounce function
    function handleInputChange(event) {
        const query = event.target.value.trim();

        const isValid = /^[a-zA-ZıİşŞğĞüÜöÖçÇ\s]+$/.test(query);

        if (isValid) {
            debouncedSearchFood(query);
        } else {
            console.error('Invalid input: Only letters and spaces are allowed');
        }
    }

    // Function to close the search container
    function closeSearchContainer() {
        setFoodItems([]);
    }

    // Function to handle food item click
    function handleFoodItemClick(item) {
        setFood(item);
        closeSearchContainer();
        // Navigate to FoodData page with the selected food item data
        navigate('/fooddata', { state: { foodItem: item, details, mealNumber, eatenDate } });
    }

    return (
        <section className="container search-container">
            <Header />
            <Footer />
            <div className="search">
                <input className="search-inp" type="search" onChange={handleInputChange} maxLength={50} placeholder="Yiyecek Arayın" />
                {loading ? (
                    <div className="spinner-container-searchFood">
                        <ClipLoader
                            color={color}
                            loading={loading}
                            size={25}
                            aria-label="Loading Spinner"
                            data-testid="loader"
                        />
                    </div>
                ) : (
                    foodItems.length !== 0 && (
                        <div className="search-results">
                            {foodItems.map((item) => (
                                <p className="item" onClick={() => handleFoodItemClick(item)} key={item._id}>{item.NameTr}</p>
                            ))}
                        </div>
                    )
                )}
            </div>
            {/* {food !== null ? (
                <FoodData food={food} quantity={quantity} details={details} id={id} mealNumber={mealNumber} eatenDate={eatenDate} />
            ) : null} */}
        </section>
    );
}