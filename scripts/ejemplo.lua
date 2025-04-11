-- Script de ejemplo para Roblox
local Players = game:GetService("Players")
local player = Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()

-- Función para mostrar un mensaje
local function mostrarMensaje(texto)
    game.StarterGui:SetCore("SendNotification", {
        Title = "Ejecutor",
        Text = texto,
        Duration = 5
    })
end

-- Ejecutar cuando el personaje esté listo
if character then
    mostrarMensaje("Script ejecutado correctamente!")
    
    -- Ejemplo de funcionalidad: Hacer el personaje invisible
    for _, part in pairs(character:GetDescendants()) do
        if part:IsA("BasePart") then
            part.Transparency = 0.5
        end
    end
end 