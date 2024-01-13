package backend

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

// Constants for database, set in .env file if necessary
const (
	host = "localhost"
	port = 5432
)

// Task struct w/o the user_uuid
type Item struct {
	TaskNum int    `json:"id"`
	Task    string `json:"task"`
	Status  bool   `json:"status"`
}

// Connect to PostgreSQL database and also retrieve user_id from users table
func OpenConnection() (*sql.DB, string) {
	// Getting constants from .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	user, ok := os.LookupEnv("USER")
	if !ok {
		log.Fatal("Error loading env variables")
	}
	password, ok := os.LookupEnv("PASSWORD")
	if !ok {
		log.Fatal("Error loading env variables")
	}
	dbname, ok := os.LookupEnv("DB_NAME")
	if !ok {
		log.Fatal("Error loading env variables")
	}

	// connect to database
	// 1. create the connection string
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	// 2. validate the arguments provided, doesn't create connection to database
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	// 3. actually open the connection to the database
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	// add email to users table if not present
	email := GetEmail()
	addEmail := `INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING;`
	_, err = db.Exec(addEmail, email)
	if err != nil {
		panic(err)
	}

	// get user_id
	var userId string
	getUser := `SELECT user_id FROM users WHERE email = $1;`
	err = db.QueryRow(getUser, email).Scan(&userId)
	if err != nil {
		panic(err)
	}

	return db, userId
}

func GetEmail() string {
	// load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// The field in the JWT to which email is added
	key, ok := os.LookupEnv("NAMESPACE_DOMAIN")
	if !ok {
		log.Fatal("Error loading env variables (namespace domain)")
	}
	// extract token via Middleware function
	_, token := Middleware()
	// parse token for email and convert it to string
	email := token[key].(string)
	return email
}

// Get complete list of tasks
var GetList = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Set header to json content, otherwise data appear as plain text
	w.Header().Set("Content-Type", "application/json")

	// Connect to database and get user_id
	db, userId := OpenConnection()

	// Return all tasks (rows) as id, task, status where the user_uuid of the task is the same as user_id we have obtained in previous step
	rows, err := db.Query("SELECT id, task, status FROM tasks JOIN users ON tasks.user_uuid = users.user_id WHERE user_id = $1", userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}
	defer rows.Close()
	defer db.Close()

	// Initializing slice like this and not "var items []Item" because aforementioned method returns null when empty thus leading to errors,
	// while used method returns empty slice
	items := make([]Item, 0)
	// Add each task to array of Items
	for rows.Next() {
		var item Item
		err := rows.Scan(&item.TaskNum, &item.Task, &item.Status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			panic(err)
		}
		items = append(items, item)
	}

	// Output with indentation
	// convert items into byte stream
	itemBytes, _ := json.MarshalIndent(items, "", "\t")
	// write to w
	_, err = w.Write(itemBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		panic(err)
	}

	w.WriteHeader(http.StatusOK)

	// Alternatively, output without indentation
	// NewEncoder: WHERE should the encoder write to
	// Encode: encode WHAT
	// _ = json.NewEncoder(w).Encode(items)
})

// Add new task
var AddTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Set header to json content, otherwise data appear as plain text
	w.Header().Set("Content-Type", "application/json")

	// decode the requested data to 'newTask'
	var newTask Item

	// NewDecoder: Decode FROM WHERE
	// Decode: WHERE TO STORE the decoded data
	err := json.NewDecoder(r.Body).Decode(&newTask)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	db, userId := OpenConnection()
	defer db.Close()

	sqlStatement := `INSERT INTO tasks (task, status, user_uuid) VALUES ($1, $2, $3) RETURNING id, task, status;`

	// retrieve the task after creation from the database and store its details in 'updatedTask'
	var updatedTask Item
	err = db.QueryRow(sqlStatement, newTask.Task, newTask.Status, userId).Scan(&updatedTask.TaskNum, &updatedTask.Task, &updatedTask.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	w.WriteHeader(http.StatusOK)

	// gives the new task as the output
	_ = json.NewEncoder(w).Encode(updatedTask)
})

// delete task
var DeleteTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Set header to json content, otherwise data appear as plain text
	w.Header().Set("Content-Type", "application/json")

	// getting the task id from the request URL
	vars := mux.Vars(r) // vars includes all variables in the request URL route.
	// For example, in "/list/delete/{id}", "id" is a variable (of type string)

	number, err := strconv.Atoi(vars["id"]) // convert the string id to integer and assign it to variable "number"
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	db, userId := OpenConnection()
	sqlStatement := `DELETE FROM tasks WHERE id = $1 AND user_uuid = $2;`

	// Note that unlike before, we assign a variable instead of _ to the first returned value by db.Exec,
	// as we need it to confirm that the row was deleted
	res, err := db.Exec(sqlStatement, number, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	// verifying if row was deleted
	_, err = res.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	// to get the remaining tasks, same as the GET function
	rows, err := db.Query("SELECT id, task, status FROM tasks JOIN users ON tasks.user_uuid = users.user_id WHERE user_id = $1;", userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}
	defer rows.Close()
	defer db.Close()

	// var items []Item
	items := make([]Item, 0)
	for rows.Next() {
		var item Item
		err := rows.Scan(&item.TaskNum, &item.Task, &item.Status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			panic(err)
		}
		items = append(items, item)
	}

	// output with indentation
	// convert items into byte stream
	itemBytes, _ := json.MarshalIndent(items, "", "\t")

	// write to w
	_, err = w.Write(itemBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		panic(err)
	}

	w.WriteHeader(http.StatusOK)
})

// edit task
var EditTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Set header to json content, otherwise data appears as plain text
	w.Header().Set("Content-Type", "application/json")

	// get the task id from the request url
	vars := mux.Vars(r)
	number, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	sqlStatement := `UPDATE tasks SET task = $2 WHERE id = $1 AND user_uuid = $3 RETURNING id, task, status;`

	// decode the requested data to 'newTask'
	var newTask Item

	// NewDecoder: Decode FROM WHERE
	// Decode: WHERE TO STORE the decoded data
	err = json.NewDecoder(r.Body).Decode(&newTask)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	db, userId := OpenConnection()
	defer db.Close()

	// retrieve the task after creation from the database and store its details in 'updatedTask'
	var updatedTask Item
	err = db.QueryRow(sqlStatement, number, newTask.Task, userId).Scan(&updatedTask.TaskNum, &updatedTask.Task, &updatedTask.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	w.WriteHeader(http.StatusOK)

	// gives the new task as the output
	_ = json.NewEncoder(w).Encode(updatedTask)
})

// change the task status
var DoneTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Set header to json content, otherwise data appear as plain text
	w.Header().Set("Content-Type", "application/json")

	// get the task id from the request url
	vars := mux.Vars(r)
	number, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	// store current status of the task from database
	var currStatus bool

	// store updated task
	var updatedTask Item

	sqlStatement1 := `SELECT status FROM tasks WHERE id = $1 AND user_uuid = $2;`
	sqlStatement2 := `UPDATE tasks SET status = $2 WHERE id = $1 AND user_uuid = $3 RETURNING id, task, status;`

	db, userId := OpenConnection()
	defer db.Close()

	// get current status of the task
	err = db.QueryRow(sqlStatement1, number, userId).Scan(&currStatus)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}

	// changing the status of the task
	err = db.QueryRow(sqlStatement2, number, !currStatus, userId).Scan(&updatedTask.TaskNum, &updatedTask.Task, &updatedTask.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}
	w.WriteHeader(http.StatusOK)

	// gives the new task as the output
	_ = json.NewEncoder(w).Encode(updatedTask)
})
