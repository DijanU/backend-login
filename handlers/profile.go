package handlers

import (
	"encoding/json"
	"net/http"
)

// GetProfileHandler maneja las solicitudes GET a /profile
func GetProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Obtener los claims desde el contexto
	claimsValue := r.Context().Value("claims")
	if claimsValue == nil {
		http.Error(w, "No claims found", http.StatusUnauthorized)
		return
	}

	claims, ok := claimsValue.(*Claims)
	if !ok {
		http.Error(w, "Invalid claims type", http.StatusInternalServerError)
		return
	}

	// Retornar la información del perfil como JSON
	response := map[string]interface{}{
		"userId":   claims.UserID,
		"username": claims.Username,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
