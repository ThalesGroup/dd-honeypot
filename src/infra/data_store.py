import abc
import json
import sqlite3
from abc import ABC
from enum import Enum
from typing import Dict, Optional, Any


class SearchMethod(Enum):
    EXACT = 1
    LIKE = 2


_DATA_FIELD = "response"


class DataStore(ABC):
    def __init__(
        self,
        db_name: str,
        structure: Dict[str, str],
        search_method: Dict[str, SearchMethod] = None,
    ):
        self._db_name = db_name
        self._structure = structure
        self._search_method = search_method if search_method else {}

    @abc.abstractmethod
    def load_static_content(self, file_name: str) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def clear(self) -> int:
        raise NotImplementedError()

    @abc.abstractmethod
    def store(self, search_terms: Dict[str, Any], value: str) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def search(self, search_terms: Dict[str, Any]) -> Optional[str]:
        raise NotImplementedError()

    @abc.abstractmethod
    def delete(self, search_terms: Dict[str, Any]) -> bool:
        raise NotImplementedError()

    @abc.abstractmethod
    def dump(self, file_name: str) -> int:
        raise NotImplementedError()


class SqliteDataStore(DataStore):
    _TABLE_NAME = "honeypot_data"

    def __init__(
        self,
        db_name: str,
        structure: Dict[str, str],
        data_field: str = "data",
        search_method: Dict[str, SearchMethod] = None,
    ):
        super().__init__(db_name, structure, search_method)
        with sqlite3.connect(self._db_name) as conn:
            create_table_sql = f"""
            CREATE TABLE IF NOT EXISTS {self._TABLE_NAME} (
                is_static BOOLEAN,
                {', '.join(f'{key} {value}' for key, value in self._structure.items())},
                data TEXT
            )"""
            conn.execute(create_table_sql)
            conn.commit()

    def load_static_content(self, file_name: str) -> None:
        with open(file_name) as f:
            for line in f:
                line_json = json.loads(line)
                search_terms = {
                    key: line_json[key]
                    for key in self._structure.keys()
                    if key in line_json
                }
                search_terms["is_static"] = True
                self.store(search_terms, line_json[_DATA_FIELD])

    def clear(self) -> int:
        with sqlite3.connect(self._db_name) as conn:
            cursor = conn.execute(f"DELETE FROM {self._TABLE_NAME} WHERE NOT is_static")
            conn.commit()
            return cursor.rowcount

    def store(self, search_terms: Dict[str, Any], data: str) -> None:
        with sqlite3.connect(self._db_name) as conn:
            filtered_terms = {k for k in search_terms if k in self._structure}
            columns = f"{', '.join(filtered_terms)}, is_static, data"
            placeholders = ", ".join(["?"] * (len(filtered_terms) + 2))
            sql = f"INSERT INTO {self._TABLE_NAME} ({columns}) VALUES ({placeholders})"
            conn.execute(
                sql, [str(search_terms[k]) for k in filtered_terms] + [False, data]
            )
            conn.commit()

    def search(self, search_terms: Dict[str, Any]) -> Optional[str]:
        with sqlite3.connect(self._db_name) as conn:
            values, where_clause = self.build_where_clause(search_terms)
            sql = f"SELECT data FROM {self._TABLE_NAME} WHERE {where_clause}"
            cursor = conn.execute(sql, values)
            row = cursor.fetchone()
            return row[0] if row else None

    def delete(self, search_terms: Dict[str, Any]) -> bool:
        with sqlite3.connect(self._db_name) as conn:
            values, where_clause = self.build_where_clause(search_terms)
            sql = f"DELETE FROM {self._TABLE_NAME} WHERE {where_clause}"
            cursor = conn.execute(sql, values)
            conn.commit()
            return cursor.rowcount > 0

    def build_where_clause(self, search_terms: dict[str, Any]) -> (list, str):
        conditions = []
        values = []
        for key in self._structure:
            if key in search_terms:
                value = str(search_terms[key])
                search_method = self._search_method.get(key, SearchMethod.EXACT).value
                if search_method == SearchMethod.EXACT.value:
                    conditions.append(f"{key} = ?")
                elif search_method == SearchMethod.LIKE.value:
                    conditions.append(f"{key} LIKE ?")
                    value = f"%{value}%"
                values.append(value)
        where_clause = " AND ".join(conditions)
        return values, where_clause

    def dump(self, file_name: str) -> int:
        with sqlite3.connect(self._db_name) as conn:
            cursor = conn.execute(
                f"SELECT {','.join(self._structure)},data FROM {self._TABLE_NAME} WHERE NOT is_static"
            )
            rows_num = 0
            with open(file_name, "w") as f:
                rows = cursor.fetchmany(100)
                while rows:
                    for row in rows:
                        data = {key: value for key, value in zip(self._structure, row)}
                        data[_DATA_FIELD] = row[-1]
                        f.write(json.dumps(data) + "\n")
                        rows_num += 1
                    rows = cursor.fetchmany(100)
            return rows_num
