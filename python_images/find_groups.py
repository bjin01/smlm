import os

import psycopg
import sys
import yaml

def execute_sql(dbname, user, password, host='localhost', port=5432, query=""):
    """
    Connects to a PostgreSQL database and lists all tables in the public schema.
    """
    try:
        print(f"Connecting to database '{dbname}' on {host}...")
        
        # Establishing the connection
        # Using a context manager ensures the connection is closed automatically
        with psycopg.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        ) as conn:

            # Create a cursor to execute SQL commands
            with conn.cursor() as cur:
                # SQL query to fetch table names from the information_schema
                query = query
                
                cur.execute(query)
                rows = cur.fetchall()
    except psycopg.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    return rows

def get_all_minions(sumagroups, dbname, user, password, host='localhost', port=5432):
    query = """
            select id, name, org_id from rhnserver;
            """
    rows = execute_sql(dbname, user, password, host, port, query)
    if not rows:
        print(f"No rows found in get_all_minions.")
        return



def get_suma_groups(sumagroups, dbname, user, password, host='localhost', port=5432):
    query = """
            select name from rhnservergroup where group_type is null;
            """
    rows = execute_sql(dbname, user, password, host, port, query)
    if not rows:
        print(f"No rows found in get_suma_groups.")
        return

    for row in rows:
        sumagroups[row[0]] = []


def get_minion_groups(sumagroups, dbname, user, password, host='localhost', port=5432):
    """
    Connects to a PostgreSQL database and lists all tables in the public schema.
    """
    
    query = """
                    SELECT
                        rhnserver.name,
                        rhnservergroup.name,
                        web_customer.name,
                        rhnservergroup.org_id,
                        rhnservergroupmembers.server_id
                    FROM rhnservergroup
                    INNER JOIN rhnservergroupmembers
                        ON rhnservergroup.id = rhnservergroupmembers.server_group_id
                    INNER JOIN web_customer
                        ON web_customer.id = rhnservergroup.org_id
                    INNER JOIN rhnserver
                        ON rhnserver.id = rhnservergroupmembers.server_id
                    AND rhnserver.org_id = rhnservergroup.org_id
                    WHERE rhnservergroup.group_type IS NULL;
            """
                    
    rows = execute_sql(dbname, user, password, host, port, query)

    if not rows:
        print(f"No rows found in get_minion_groups.")
        return

    print(f"\Result from get_minion_groups':")

                
    for row in rows:
        if row[1] != "" and row[1] is not None and row[1] in sumagroups.keys():
            sumagroups[row[1]].append(row[0])
                
    print(f" - {sumagroups}")

def write_salt_pillar(sumagroups, pillar_dir="/srv/pillar", pillar_name="sumagroups", pillar_file="init.sls"):
    final_data = dict()
    final_data[pillar_name] = sumagroups

    with open(f"{pillar_dir}/{pillar_name}/{pillar_file}", "w") as f:
        yaml.dump(final_data, f, default_flow_style=False, indent=4, width=80)

def refresh_minion_pillar(minion_id):
    import subprocess
    try:
        result = subprocess.run(["salt", minion_id, "saltutil.refresh_pillar"], capture_output=True, text=True, check=True)
        print(f"Successfully refreshed pillar for minion '{minion_id}': {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error refreshing pillar for minion '{minion_id}': {e.stderr}", file=sys.stderr)

if __name__ == "__main__":
    sumagroups = dict()

    # Update these credentials to match your PostgreSQL configuration
    dbname = os.getenv('DB_NAME', 'susemanager')
    user = os.getenv('DB_USER', 'spacewalk')
    password = os.getenv('DB_PWD', 'spacewalk')
    host = os.getenv('DB_HOST', 'db')
    port = int(os.getenv('DB_PORT', 5432))

    get_all_minions(sumagroups, dbname=dbname, user=user, password=password, host=host, port=port)
    get_suma_groups(sumagroups, dbname=dbname, user=user, password=password, host=host, port=port)
    get_minion_groups(sumagroups, dbname=dbname, user=user, password=password, host=host, port=port)
    write_salt_pillar(sumagroups)
