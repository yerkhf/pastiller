import math

from app import calcular_bmi, tiempo_hasta_nivel


def test_tiempo_hasta_nivel_basic():
    k = math.log(2) / 4
    assert abs(tiempo_hasta_nivel(50, k) - 4.0) < 1e-9


def test_calcular_bmi_basic():
    assert calcular_bmi(70, 175) == 22.857142857142858
