import { useCallback, useRef, useState } from 'react'

export const useLongPress = (onLongPress, onClick, { threshold = 500, shouldPreventDefault = true } = {}) => {
  const [longPressTriggered, setLongPressTriggered] = useState(false)
  const timeout = useRef()
  const target = useRef()

  const start = useCallback(
    (event) => {
      if (shouldPreventDefault && event.target) {
        event.target.addEventListener('touchmove', preventDefault, { passive: false })
      }
      target.current = event.target
      timeout.current = setTimeout(() => {
        onLongPress(event)
        setLongPressTriggered(true)
      }, threshold)
    },
    [onLongPress, threshold, shouldPreventDefault]
  )

  const clear = useCallback(
    (event, shouldTriggerClick = true) => {
      timeout.current && clearTimeout(timeout.current)
      shouldTriggerClick && !longPressTriggered && onClick && onClick(event)
      setLongPressTriggered(false)
      if (shouldPreventDefault && target.current) {
        target.current.removeEventListener('touchmove', preventDefault)
      }
    },
    [shouldPreventDefault, onClick, longPressTriggered]
  )

  const preventDefault = (event) => {
    if (!event.defaultPrevented) {
      event.preventDefault()
    }
  }

  return {
    onMouseDown: (e) => start(e),
    onTouchStart: (e) => start(e),
    onMouseUp: (e) => clear(e),
    onMouseLeave: (e) => clear(e, false),
    onTouchEnd: (e) => clear(e),
    onTouchCancel: (e) => clear(e, false),
  }
}