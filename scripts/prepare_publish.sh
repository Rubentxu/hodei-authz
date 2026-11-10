#!/bin/bash
# Script para preparar crates para publicación
# Cambia dependencias workspace a versiones específicas

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}🔧 Preparando crates para publicación...${NC}"
echo ""

# Crear backup
echo "📦 Creando backup de Cargo.toml..."
find crates -name "Cargo.toml" -exec cp {} {}.backup \;

# Cambiar dependencias internas a versiones específicas
echo "🔄 Cambiando dependencias workspace a versiones específicas..."

# hodei-authz
sed -i 's/hodei-hrn = { workspace = true }/hodei-hrn = "0.1.0"/g' crates/hodei-authz/Cargo.toml
sed -i 's/hodei-derive = { workspace = true }/hodei-derive = "0.1.0"/g' crates/hodei-authz/Cargo.toml

# hodei-authz-postgres
sed -i 's/hodei-authz = { workspace = true }/hodei-authz = "0.1.0"/g' crates/hodei-authz-postgres/Cargo.toml

# hodei-authz-redis
sed -i 's/hodei-authz = { workspace = true }/hodei-authz = "0.1.0"/g' crates/hodei-authz-redis/Cargo.toml

# hodei-authz-axum
sed -i 's/hodei-authz = { workspace = true }/hodei-authz = "0.1.0"/g' crates/hodei-authz-axum/Cargo.toml

# hodei-authz-sdk
sed -i 's/hodei-hrn = { workspace = true }/hodei-hrn = "0.1.0"/g' crates/hodei-authz-sdk/Cargo.toml
sed -i 's/hodei-authz = { workspace = true }/hodei-authz = "0.1.0"/g' crates/hodei-authz-sdk/Cargo.toml
sed -i 's/hodei-derive = { workspace = true }/hodei-derive = "0.1.0"/g' crates/hodei-authz-sdk/Cargo.toml
sed -i 's/hodei-authz-postgres = { workspace = true, optional = true }/hodei-authz-postgres = { version = "0.1.0", optional = true }/g' crates/hodei-authz-sdk/Cargo.toml
sed -i 's/hodei-authz-redis = { workspace = true, optional = true }/hodei-authz-redis = { version = "0.1.0", optional = true }/g' crates/hodei-authz-sdk/Cargo.toml
sed -i 's/hodei-authz-axum = { workspace = true, optional = true }/hodei-authz-axum = { version = "0.2.0", optional = true }/g' crates/hodei-authz-sdk/Cargo.toml

echo ""
echo -e "${GREEN}✅ Crates preparados para publicación${NC}"
echo ""
echo "📋 Cambios realizados:"
echo "  • hodei-hrn: Sin cambios (sin dependencias internas)"
echo "  • hodei-derive: Sin cambios (sin dependencias internas)"
echo "  • hodei-authz: workspace → versiones específicas"
echo "  • hodei-authz-postgres: workspace → versiones específicas"
echo "  • hodei-authz-redis: workspace → versiones específicas"
echo "  • hodei-authz-axum: workspace → versiones específicas"
echo "  • hodei-authz-sdk: workspace → versiones específicas"
echo ""
echo -e "${YELLOW}⚠️  Backups creados en: crates/*/Cargo.toml.backup${NC}"
echo ""
echo "Próximos pasos:"
echo "  1. Revisar cambios: git diff crates/*/Cargo.toml"
echo "  2. Publicar: ./publish.sh"
echo "  3. Revertir: ./restore_workspace.sh"
