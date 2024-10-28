import React from "react";
import { useState, useEffect } from "react";
import { UserContext } from "../../context/UserContext";
import { useContext } from "react";
import ObjectId from 'bson-objectid';
import { useNavigate } from "react-router-dom";

export default function DeleteCopyFunction({selectedFoods, setFoodsByMeal, mealNumber, foodsByMeal, copyDate, refreshFoods, setMessage}) {

    let loggedData = useContext(UserContext);
    const navigate = useNavigate();
    const [csrfToken, setCsrfToken] = useState('');

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

    // Function to handle delete button click
    const handleDeleteClick = () => {
        console.log("Selected foods to delete:", selectedFoods);

        fetch(`http://localhost:8000/deleteFoods`, {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                "csrf-token": csrfToken
            },
            body: JSON.stringify({ foods: selectedFoods.map(food => ({ _id: food._id })) }),
            credentials: 'include'
        })
        .then((response) => {
            if (!response.ok) {
                throw new Error("Network response was not ok");
            }
            return response.json();
        })
        .then((data) => {
            console.log("Selected foods deleted successfully:", data.message);
            // Refresh the food items after deletion
            refreshFoods();
        })
        .catch((error) => {
            console.error("Error deleting selected foods:", error);
        });
    };

    const handleCopyItems = () => {
        console.log("Copying items-2:", selectedFoods);
        console.log("Copy Date in handleCopyItems:", copyDate);
        console.log("Copy Meal Number in handleCopyItems:", mealNumber);

        if (selectedFoods.length > 0) {
            const copiedItemsWithId = selectedFoods.map(item => ({
                ...item,
                _id: new ObjectId().toString(),
            }));

            console.log("Copied items with IDs:", copiedItemsWithId);
            const convertedCopyDate = new Date(copyDate).toISOString().slice(0, 10);

            fetch(`http://localhost:8000/track/copy`, {
                method: "POST",
                body: JSON.stringify({
                    copiedItems: copiedItemsWithId.map(item => ({
                        details: {
                            Name: item.details.Name,
                            foodId: item.details.foodId,
                            Calorie: item.details.Calorie,
                            Protein: item.details.Protein,
                            Carbohydrate: item.details.Carbohydrate,
                            Fat: item.details.Fat,
                            Fiber: item.details.Fiber,
                        },
                        foodId: item.foodId,
                        quantity: item.quantity,
                        mealNumber: mealNumber,  // Use the mealNumber prop here
                        eatenDate: convertedCopyDate
                    })),
                    userId: loggedData.loggedUser.userid,
                }),
                headers: {
                    "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                    "Content-Type": "application/json",
                    "csrf-token": csrfToken
                },
                credentials: 'include'
            })
            .then(response => {
                console.log("Response status:", response.status);
                if (!response.ok) {
                    throw new Error("Network response was not ok");
                }
                return response.json();
            })
            .then(data => {
                console.log("Copy successful:", data);
                // Refresh the food items after copying
                refreshFoods();
                // Set success message
                setMessage({ type: "success-copy", text: "Başarıyla kopyalandı!" });
                setTimeout(() => {
                    setMessage({ type: "", text: "" })
                }, 3000);
            })
            .catch(error => {
                console.error("Error copying items:", error);
                // Set error message
                setMessage({ type: "error", text: "Kopyalama sırasında bir hata oluştu." });
                setTimeout(() => {
                    setMessage({ type: "", text: "" })
                }, 2000);
            });
        } else {
            console.log("No selected items to copy.");
            setMessage({ type: "info", text: "Kopyalanacak öğe seçilmedi." });
        }
    };

    const handleBackClick = () => {
        navigate("/diet"); // Navigate to the diet page
    };

    return (
        <div className="meal-function-footer-wrapper">
            <footer className="meal-function-footer">
                <div>
                    <button className="meal-function-footer-button" onClick={handleBackClick}>
                        <i className="fa-solid fa-arrow-left"></i>
                    </button>
                </div>
                <div>
                    <button className="meal-function-footer-button" onClick={handleDeleteClick}>Sil</button>
                </div>
                <div>
                    <button className="meal-function-footer-button" onClick={handleCopyItems}>Kopyala</button>
                </div>
            </footer>
        </div>
    );
}
